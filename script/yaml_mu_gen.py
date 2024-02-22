#!/usr/bin/env python3
import argparse
import contextlib
import inspect
import os
import tpm2_pytss
import subprocess
import yaml
from pycparser import c_parser, c_ast
import sys
import tempfile
import textwrap
from tpm2_pytss.types import TPM2B_SIMPLE_OBJECT

class CComplex(object):
    @property
    def name(self):
        return self._name
    
    @property
    def fields(self):
        return self._fields
    
    def __init__(self, name: str, fields: dict):
        self._name = name
        self._fields = fields

    def __str__(self):
        return f"{self._name}:\n\t{self._fields}"

class CStruct(CComplex):
    pass

class CUnion(CComplex):
    pass

class CScalar(object):
    @property
    def name(self):
        return self._name
    
    @property
    def size(self) -> int:
        return self._size
    
    @property
    def signed(self) -> bool:
        return self._signed
    
    def __init__(self, name: str, size: int, signed: bool):
        self._name = name
        self._size = size
        self._signed = signed

    def __str__(self):
        return (f"{self._name}:\n\tsigned: {self._signed}\n\tsize: {self._size}")

class CTypeParser(object):

    def __init__(self, include_path: str):
        self.include_path = include_path

    def _run_cpp(self) -> str:
        # Run the C preprocessor (cpp) on the header file
        result = subprocess.run(['gcc', '-E', self.include_path], capture_output=True, text=True)
        preprocessed_code = result.stdout
        return preprocessed_code
    
    def _get_type_size(self, type_: str) -> (int, bool):
        
        prog = textwrap.dedent(f"""
        #include <stdio.h>
        #include "{self.include_path}"
        
        int main(int argc, char *argv[]) {{
            (void) argc;
            (void) argv;
                
            {type_} x = (typeof(x))-1;
            x >>= 1;
            printf("sizeof: %zu\\n", sizeof(x));
            printf("signed: %d\\n", x & 1 << (sizeof(x) * 8 - 1));
    
            return 0;
        }}
        """)
        
        with contextlib.ExitStack() as stack:
            tmp_dir = tempfile.TemporaryDirectory()
            stack.enter_context(tmp_dir)
            
            tmp_src = open(os.path.join(tmp_dir.name, f"{type_}.c"), mode="w+t")
            stack.enter_context(tmp_src)
            
            tmp_bin = os.path.join(tmp_dir.name, f"{type_}.bin")
            
            tmp_src.write(prog)
            tmp_src.flush()
            
            result = subprocess.run(['gcc', '-o', tmp_bin, tmp_src.name ], capture_output=True)
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.stderr.decode(), cmd="gcc")
            
            type_data = subprocess.run([tmp_bin], capture_output=True, text=True, check=True)
            y = yaml.safe_load(type_data.stdout)
            return (int(y["sizeof"]), bool(y["signed"]))
        
    
    @staticmethod
    def _parse_struct_decl(decl):
        struct_name = decl.name
        field_map = {}
    
        for field_decl in decl.decls:
            if isinstance(field_decl, c_ast.Decl):
                field_name = field_decl.name
                field_type = field_decl.type
                if isinstance(field_type, c_ast.ArrayDecl):
                    field_type = field_type.type
    
                assert isinstance(field_type, c_ast.TypeDecl)
                try:
                    sub_type = field_type.type
                    first_type = sub_type.names[0]
                except Exception as e:
                    raise e
                field_map[field_name] = str(first_type)
    
        return struct_name, field_map
    
    @staticmethod
    def _parse_typedef_decl(decl):
        try:
            name = decl.name
            type_ = getattr(decl.type.type, "names", None)
            if type_:
                type_name = type_[0]
            else:
                type_name = decl.type.type.name
            return name, type_name
        except:
            return None, None
    
    def get_type_map(self) -> dict:
        preprocessed_code = self._run_cpp()
    
        parser = c_parser.CParser()
        ast = parser.parse(preprocessed_code, filename=self.include_path)

        type_map = {}
       
        for node in ast.ext:
            if node.coord.file != self.include_path:
                continue
            # TODO UNIONS
            if isinstance(node, c_ast.Decl) and isinstance(node.type, c_ast.Struct) or isinstance(node.type, c_ast.Union):
                struct_name, field_map = CTypeParser._parse_struct_decl(node.type)
                cls =CStruct if isinstance(node.type, c_ast.Struct) else CUnion
                type_map[struct_name] = cls(struct_name, field_map) 
            #elif isinstance(node, c_ast.Typedef) and not isinstance(node.type.type, c_ast.Struct) and not isinstance(node.type.type, c_ast.Union):
            elif isinstance(node, c_ast.IdentifierType):
                name, _type = CTypeParser._parse_typedef_decl(node)
                if name is None:
                    continue
                size, signed = self._get_type_size(_type)
                type_map[name] = CScalar(_type, size, signed)
    
        return type_map


def get_subclasses(base_class, package):
    subclasses = []
    for _, obj in inspect.getmembers(package):
        if inspect.isclass(obj) and issubclass(obj, base_class) and obj != base_class:
            subclasses.append(obj)
    return subclasses


def print_proto(name):
    t = textwrap.dedent(
        f"""
        TSS2_RC
        Tss2_MU_YAML_{name}_Marshal(
            const {name} *src,
            char        **yaml);

        TSS2_RC
        Tss2_MU_YAML_{name}_Unmarshal(
            const char *yaml,
            size_t      yaml_len,
            {name}     *dest);
    """
    )

    sys.stdout.write(t)

def print_test_protos(name):
    t = textwrap.dedent(
        f"""
        void
        test_{name}_good(void **state);

        void
        test_{name}_zero(void **state);

        void
        test_{name}_null(void **state);
        """
    )
    sys.stdout.write(t)

def print_cmocka_test(name):
    print(f"cmocka_unit_test(test_{name}_good),")
    print(f"cmocka_unit_test(test_{name}_zero),")
    print(f"cmocka_unit_test(test_{name}_null),")

def callable_tpm2b_test_protos():
    subclasses = get_subclasses(TPM2B_SIMPLE_OBJECT, package=tpm2_pytss)
    for s in subclasses:
        print_test_protos(s.__name__)

def callable_tpm2b_tests():
    subclasses = get_subclasses(TPM2B_SIMPLE_OBJECT, package=tpm2_pytss)
    for s in subclasses:
        x = s()
        attrs = dir(x._cdata)
        attrs.remove("size")
        assert len(attrs) == 1
        name = s.__name__
        field = attrs[0]

        # I was hoping to get the data type size, but no luck
        # just make it 16, that fits inside everything like
        # TPM2B_IV
        size = 16
        raw_bytes = os.urandom(size)
        hex_list = ", ".join([f"0x{byte:02x}" for byte in raw_bytes])
        w = textwrap.wrap(hex_list, 88)
        hex_list = "\n                    ".join(w)

        hex_str = raw_bytes.hex()
        w = textwrap.wrap(hex_str, 88)
        w = [f'"{x}"' for x in w]
        hex_str = "\n                ".join(w)

        t = textwrap.dedent(
            f"""
            void
            test_{name}_good(void **state)
            {{
                UNUSED(state);

                static const {name} src = {{
                    .size = {size},
                    .{field} = {{
                        {hex_list}
                    }}
                }};

                TEST_COMMON_GOOD({name}, {field},
                    {hex_str.strip()},
                    src);
            }}

            void
            test_{name}_zero(void **state)
            {{
                UNUSED(state);

                TEST_COMMON_ZERO({name}, {field});
            }}

            void
            test_{name}_null(void **state)
            {{
                TEST_COMMON_NULL({name}, {field});
            }}
        """
        )

        sys.stdout.write(t)

def callable_tpms_simple_tests():
    s = get_tpms_simple()
    
    t = textwrap.dedent("""
        void test_{name}_zero(void **state) {{
            TEST_COMMON_ZERO({name});
        }}
    
        void test_{name}_null(void **state) {{
            TEST_COMMON_NULL({name});
        }}
    
        void test_{name}_good(void **state) {{
            // TODO Implement Me!
            assert_true(0);
        }}
        """)
    
    for x in s:
        print(t.format(name=x))

def callable_tpms_simple_test_protos():
    s = get_tpms_simple()
    for x in s:
        print_test_protos(x)

def callabale_tpms_simple_test_list():
    s = get_tpms_simple()
    for x in s:
        print_cmocka_test(x)

def callable_tpm2b_protos():
    subclasses = get_subclasses(TPM2B_SIMPLE_OBJECT, package=tpm2_pytss)
    for s in subclasses:
        name = s.__name__
        print_proto(name)

def callable_tpm2b_test_list():
    subclasses = get_subclasses(TPM2B_SIMPLE_OBJECT, package=tpm2_pytss)
    for s in subclasses:
        print_cmocka_test(s.__name__)

def callable_tpm2b_defines():
    subclasses = get_subclasses(TPM2B_SIMPLE_OBJECT, package=tpm2_pytss)
    for s in subclasses:
        x = s()
        attrs = dir(x._cdata)
        attrs.remove("size")
        assert len(attrs) == 1
        name = s.__name__
        field = attrs[0]
        print(f"SIMPLE_TPM2B_MARSHAL({name}, {field})")
        print(f"SIMPLE_TPM2B_UNMARSHAL({name}, {field})")


def get_tpms_simple():
    l = []
    for _, obj in inspect.getmembers(tpm2_pytss):
        if (
            inspect.isclass(obj)
            and obj.__name__.startswith("TPMS")
            and obj.__name__ != "TPMS_ALGORITHM_DESCRIPTION"
            and obj.__name__ == "TPMS_ALG_PROPERTY"
        ):
            x = obj()
            fields = [
                f
                for f in dir(x)
                if not f.startswith("_") and not f == "marshal" and not f == "unmarshal"
            ]

            fields = [getattr(x, f) for f in fields]

            all_scalars = True
            for f in fields:
                if not isinstance(f, int):
                    all_scalars = False
                    break

            if not all_scalars:
                continue

            l.append(obj)
    return l


def callable_tpms_complex_types():
    simples = [ x.__name__ for x in get_tpms_simple() ]
    for _, obj in inspect.getmembers(tpm2_pytss):
        if (
            inspect.isclass(obj)
            and obj.__name__.startswith("TPMS")
            and obj.__name__ not in simples
        ):
            print(obj.__name__)


def callable_tpms_simple_types():
    for s in get_tpms_simple():
        print(s.__name__)

def callable_tpms_types():
    for _, obj in inspect.getmembers(tpm2_pytss):
        if (
            inspect.isclass(obj)
            and obj.__name__.startswith("TPMS")
        ):
            print(obj.__name__)

def callable_tpms_protos():
    for _, obj in inspect.getmembers(tpm2_pytss):
        if (
            inspect.isclass(obj)
            and obj.__name__.startswith("TPMS")
            and obj.__name__ != "TPMS_ALGORITHM_DESCRIPTION"
        ):

            print_proto(obj.__name__)

def callable_tpms_code_gen():
       
    t = textwrap.dedent("""
        TSS2_RC
        Tss2_MU_YAML_{name}_Marshal(
            {name} const *src,
            char            **output)
        {{
            TSS2_RC rc = TSS2_MU_RC_GENERAL_FAILURE;
            yaml_document_t doc = { 0 };
        
            return_if_null(src, "src is NULL", TSS2_MU_RC_BAD_REFERENCE);
            return_if_null(output, "output is NULL", TSS2_MU_RC_BAD_REFERENCE);
        
            rc = doc_init(&doc);
            return_if_error(rc, "Could not initialize document");
        
            int root = yaml_document_add_mapping(&doc, NULL, YAML_ANY_MAPPING_STYLE);
            if (!root) {{
                yaml_document_delete(&doc);
                return TSS2_MU_RC_GENERAL_FAILURE;
            }}
        
            struct key_value kvs[] = {{
                {emitters}
            }};
            rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
            return_if_error(rc, "Could not add KVPs");
        
            return yaml_dump(&doc, output);
        }}
        
        TSS2_RC
        Tss2_MU_YAML_{name}_Unmarshal(
            const char          *yaml,
            size_t               yaml_len,
            {name}   *dest) {{
        
            return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
            return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);
        
            if (yaml_len == 0) {{
                yaml_len = strlen(yaml);
            }}
        
            if (yaml_len == 0) {{
                return TSS2_MU_RC_BAD_VALUE;
            }}
        
            {name} tmp_dest = { 0 };
        
            key_value parsed_data[] = {{
                    KVP_ADD_PARSER_SCALAR_U16("alg",          &tmp_dest.alg,            TPM2_ALG_ID_fromstring),
                    KVP_ADD_PARSER_SCALAR_U32("algProperties", &tmp_dest.algProperties, TPMA_ALGORITHM_fromstring)
            }};
        
            TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
            if (rc != TSS2_RC_SUCCESS) {{
                return rc;
            }}
        
            *dest = tmp_dest;
        
            return TSS2_RC_SUCCESS;
        }}""")

    p = CTypeParser('/usr/include/tss2/tss2_tpm2_types.h')
    type_map = p.get_type_map()

    emitters = []
    parsers = []
    for name, type_ in type_map.items():
        if not name.startswith("TPMS_"):
            continue
        
        field_map = type_.fields
        for f, t in field_map.items():
            field_name = f
            field_type = t
            
            emitters.append(f'KVP_ADD_UINT_TOSTRING("{field_name}", src->{field_name}, {field_type}_tostring)')
            
            field_class = type_map[field_type]
            if isinstance(field_class, CScalar):
                size = field_class.size
                sign = field_class.sign
                parsers.append(f'KVP_ADD_PARSER_SCALAR_{"I" if sign else "U"}{str(size * 8)}("{field_name}", &tmp_dest.{field_name}, {field_type}_fromstring'),
            else:
                pass
        emitters = ',\n'.join(emitters)
        parsers = ',\n'.join(parsers)
        
        # emitter list built
        t.format(emitters=emitters, parsers=parsers, name=name)

def callable_all_protos():

    callable_tpm2b_protos()
    callable_tpms_protos()

def callable_all_test_list():
    callable_tpm2b_test_list()
    callabale_tpms_simple_test_list()

def callable_tpmu_types():
    for _, obj in inspect.getmembers(tpm2_pytss):
        if inspect.isclass(obj) and obj.__name__.startswith("TPMU"):
            print(obj.__name__)


if __name__ == "__main__":

    def get_callable_functions_in_current_module():
        current_module = globals()
        return [
            name[9:]
            for name, obj in current_module.items()
            if inspect.isfunction(obj) and obj.__name__.startswith("callable_")
        ]

    choices = get_callable_functions_in_current_module()

    parser = argparse.ArgumentParser(description="Your script description")
    parser.add_argument(
        "action", choices=choices, help="Choose one option from {}".format(choices)
    )
    args = parser.parse_args()

    action = args.action
    fn = globals()[f"callable_{action}"]

    print(
        f"/* AUTOGENERATED ASSISTED CODE using yaml_mu_gen.py {sys.argv[1]}. modify with care */"
    )

    fn()

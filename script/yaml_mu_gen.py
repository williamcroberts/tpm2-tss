#!/usr/bin/env python3
import argparse
import bisect
import copy
import contextlib
import inspect
import os
import tpm2_pytss
import subprocess
import yaml
import pycparser
import re
import sys
import tempfile
import textwrap
from tpm2_pytss.types import TPM2B_SIMPLE_OBJECT
from contextlib import ExitStack


class _CMagicEq(object):
    def __eq__(self, other):
        if isinstance(other, _CMagicEq):
            return self.name == other.name
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is not NotImplemented:
            return not result
        return NotImplemented

    def __lt__(self, other):
        if isinstance(other, _CMagicEq):
            return self.name < other.name
        return NotImplemented

    def __le__(self, other):
        result_eq = self.__eq__(other)
        result_lt = self.__lt__(other)
        if result_eq is not NotImplemented:
            return result_eq or result_lt
        return NotImplemented

    def __gt__(self, other):
        if isinstance(other, _CMagicEq):
            return self.name > other.name
        return NotImplemented

    def __ge__(self, other):
        result_eq = self.__eq__(other)
        result_gt = self.__gt__(other)
        if result_eq is not NotImplemented:
            return result_eq or result_gt
        return NotImplemented


class CComplex(_CMagicEq):
    @property
    def name(self):
        return self._name

    @property
    def fields(self):
        return self._fields

    def __init__(self, name: str, fields: dict):
        self._name = name
        self._fields = fields

    def morph(self, new_name: str):
        deepcopy = copy.deepcopy(self)
        deepcopy._name = new_name
        return deepcopy


class CStruct(CComplex):
    pass


class CUnion(CComplex):
    pass


class CScalar(_CMagicEq):
    @property
    def name(self):
        return self._name

    @property
    def alias(self) -> int:
        return self._alias

    def __init__(self, name: str, alias: str):
        self._name = name
        self._alias = None if name == alias else alias

    def __str__(self):
        return f"{self._name} : {self._alias}"


class CTypeParser(object):
    def __init__(self, include_path: str):
        self._type_map = None
        self.include_path = include_path

    def _run_cpp(self) -> str:
        # Run the C preprocessor (cpresolved_typep) on the header file
        result = subprocess.run(
            ["gcc", "-E", self.include_path], capture_output=True, text=True
        )
        preprocessed_code = result.stdout
        return preprocessed_code

    def _get_defines(self):
        with open(self.include_path, "r") as f:
            c_code = f.read()

        defines = {}
        matches = re.findall(r"^#define\s+(\w+)\s+(.*)", c_code, flags=re.M)
        for m in matches:
            s = m[1]
            value_match = re.search(r"\b0[xX]([0-9a-fA-F]+)\b|\b([0-9]+)\b", s)
            if not value_match:
                continue

            defines[m[0]] = int(value_match.group(0), base=0)

        return defines

    def _get_type_size(self, type_: str) -> (int, bool):
        prog = textwrap.dedent(
            f"""
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
        """
        )

        with contextlib.ExitStack() as stack:
            tmp_dir = tempfile.TemporaryDirectory()
            stack.enter_context(tmp_dir)

            tmp_src = open(os.path.join(tmp_dir.name, f"{type_}.c"), mode="w+t")
            stack.enter_context(tmp_src)

            tmp_bin = os.path.join(tmp_dir.name, f"{type_}.bin")

            tmp_src.write(prog)
            tmp_src.flush()

            result = subprocess.run(
                ["gcc", "-o", tmp_bin, tmp_src.name], capture_output=True
            )
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.stderr.decode(), cmd="gcc")

            type_data = subprocess.run(
                [tmp_bin], capture_output=True, text=True, check=True
            )
            y = yaml.safe_load(type_data.stdout)
            return (int(y["sizeof"]), bool(y["signed"]))

    @staticmethod
    def _parse_struct_decl(decl):
        struct_name = decl.name
        field_map = {}

        for field_decl in decl.decls:
            if isinstance(field_decl, pycparser.c_ast.Decl):
                field_name = field_decl.name
                field_type = field_decl.type
                if isinstance(field_type, pycparser.c_ast.ArrayDecl):
                    field_type = field_type.type

                assert isinstance(field_type, pycparser.c_ast.TypeDecl)
                try:
                    sub_type = field_type.type
                    first_type = sub_type.names[0]
                except Exception as e:
                    raise e
                field_map[field_name] = str(first_type)

        return struct_name, field_map

    def parse(self) -> dict:
        preprocessed_code = self._run_cpp()

        parser = pycparser.c_parser.CParser()
        ast = parser.parse(preprocessed_code, filename=self.include_path)

        stdint_base_type = [
            "int",  # include this becuase of typedef int BOOL
            "int8_t",
            "uint8_t",
            "int16_t",
            "uint16_t",
            "int32_t",
            "uint32_t",
            "int64_t",
            "uint64_t",
        ]

        tpm2_base_types = [
            "INT8",
            "INT16",
            "INT32",
            "INT64",
            "UINT8",
            "UINT16",
            "UINT32",
            "UINT64",
            "BYTE",
            "BOOL",
        ]

        scalar_type_map = {}
        union_type_map = {}
        struct_type_map = {}
        typedef_type_map = {}

        for node in ast.ext:
            if (
                node.coord.file != self.include_path
                and "tss2_common.h" not in node.coord.file
            ):
                continue

            if (
                isinstance(node, pycparser.c_ast.Decl)
                and isinstance(node.type, pycparser.c_ast.Struct)
                or isinstance(node.type, pycparser.c_ast.Union)
            ):
                type_name, field_map = CTypeParser._parse_struct_decl(node.type)

                if isinstance(node.type, pycparser.c_ast.Struct):
                    struct_type_map[type_name] = CStruct(type_name, field_map)
                else:
                    union_type_map[type_name] = CUnion(type_name, field_map)
                    union_type_map[type_name] = CStruct(type_name, field_map)
            elif isinstance(node, pycparser.c_ast.Typedef):
                if isinstance(node.type, pycparser.c_ast.TypeDecl):
                    type_name = node.name
                    # if type_name.startswith("TPM2B_"):
                    aliases = getattr(node.type.type, "names", None)
                    if aliases and type_name not in aliases:
                        if len(aliases) > 1:
                            raise ValueError(
                                f"Should only have one alias, got: {len(aliases)}"
                            )
                        if type_name in typedef_type_map:
                            raise RuntimeError(
                                f"Expected only possible mapping for type: {type_name}, already had: {typedef_type_map[type_name]}"
                            )
                        # ie a UINT8 is a uint8_t

                        alias = aliases[0]
                        if alias in struct_type_map:
                            struct = struct_type_map[alias]
                            new_struct = struct.morph(new_name=type_name)
                            struct_type_map[type_name] = new_struct
                        elif alias in union_type_map:
                            union = union_type_map[alias]
                            new_union = union.morph(new_name=type_name)
                            union_type_map[type_name] = new_union
                        else:
                            if alias in stdint_base_type or alias in tpm2_base_types:
                                alias = None

                            scalar_type_map[type_name] = CScalar(type_name, alias)

        self._type_map = {
            "struct": struct_type_map,
            "union": union_type_map,
            "scalar": scalar_type_map,
            "typedef": typedef_type_map,
            "defines": self._get_defines(),
        }

    def get_type_map(self) -> dict:
        return self._type_map


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

    t = textwrap.dedent(
        """
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
        """
    )

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


def generate_simple_tpm2bs(cprsr: CTypeParser, proj_root: str):
    epilogue = textwrap.dedent(
        r"""/* SPDX-License-Identifier: BSD-2-Clause */
    /* AUTOGENRATED CODE DO NOT MODIFY */
    
    #include <stdlib.h>
    
    #include "yaml-common.h"
    
    #include "util/aux_util.h"
    #include "util/tpm2b.h"
    
    #define SIMPLE_TPM2B_MARSHAL(type, field) \
        TSS2_RC Tss2_MU_YAML_##type##_Marshal( \
                type const *src, \
                char ** yaml \
        ) \
        { \
            TSS2_RC rc = TSS2_MU_RC_GENERAL_FAILURE; \
            yaml_document_t doc = { 0 }; \
            \
            return_if_null(src, "src is NULL", TSS2_MU_RC_BAD_REFERENCE); \
            return_if_null(yaml, "output is NULL", TSS2_MU_RC_BAD_REFERENCE); \
            \
            if (src->size == 0) { \
                return TSS2_MU_RC_BAD_VALUE; \
            } \
            rc = doc_init(&doc); \
            return_if_error(rc, "Could not initialize document"); \
            \
            int root = yaml_document_add_mapping(&doc, NULL, YAML_ANY_MAPPING_STYLE); \
            if (!root) { \
                yaml_document_delete(&doc); \
                return TSS2_MU_RC_GENERAL_FAILURE; \
            } \
            \
            struct key_value kv = KVP_ADD_MARSHAL(#field, src->size, src, tpm2b_simple_generic_marshal); \
            rc = add_kvp(&doc, root, &kv); \
            return_if_error(rc, "Could not add KVP"); \
            \
            return yaml_dump(&doc, yaml); \
        }
    
    #define SIMPLE_TPM2B_UNMARSHAL(type, field) \
            TSS2_RC Tss2_MU_YAML_##type##_Unmarshal( \
                const char  *yaml, \
                size_t       yaml_len, \
                type        *dest) { \
                \
                return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE); \
                return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE); \
                \
                if (yaml_len == 0) { \
                    yaml_len = strlen(yaml); \
                } \
                \
                if (yaml_len == 0) { \
                    return TSS2_MU_RC_BAD_VALUE; \
                } \
                type tmp_dest = { 0 }; \
                key_value parsed_data = KVP_ADD_UNMARSHAL(#field, FIELD_SIZE(type, field), &tmp_dest, tpm2b_simple_generic_unmarshal); \
                \
                TSS2_RC rc = yaml_parse(yaml, yaml_len, &parsed_data, 1); \
                if (rc == TSS2_RC_SUCCESS) { \
                    *dest = tmp_dest; \
                } \
                \
                return rc; \
            }
        """
    )

    all_structs = cprsr.get_type_map()["struct"]
    simples = []
    for k, v in all_structs.items():
        if not k.startswith("TPM2B_"):
            continue

        if not isinstance(v, CStruct):
            continue

        fields = v.fields
        if len(fields) != 2:
            continue

        if "size" not in fields:
            continue

        # this IS a simple TPM2B add it to a list and keep it sorted
        bisect.insort(simples, v)

    with open(
        os.path.join(proj_root, "src", "tss2-mu-yaml", "yaml-tpm2b.c"), "w+t"
    ) as f:
        f.write(epilogue)
        f.write("\n")
        for s in simples:
            name = s.name
            field = next(x for x in s.fields.keys() if x != "size")
            f.write(f"SIMPLE_TPM2B_MARSHAL({name}, {field})\n")
            f.write(f"SIMPLE_TPM2B_UNMARSHAL({name}, {field})\n")


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
    simples = [x.__name__ for x in get_tpms_simple()]
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
        if inspect.isclass(obj) and obj.__name__.startswith("TPMS"):
            print(obj.__name__)


def callable_tpms_protos():
    for _, obj in inspect.getmembers(tpm2_pytss):
        if (
            inspect.isclass(obj)
            and obj.__name__.startswith("TPMS")
            and obj.__name__ != "TPMS_ALGORITHM_DESCRIPTION"
        ):
            print_proto(obj.__name__)


def type_to_root(scalar_map: dict, scalar: CScalar) -> CScalar:
    resolved = scalar.alias
    if resolved != None:
        resolved = scalar_map[resolved]
        resolved = type_to_root(scalar_map, resolved)
    else:
        resolved = scalar
    return resolved


def generate_tpms_code_gen(cprsr: CTypeParser, proj_root: str):
    epilogue = textwrap.dedent(
        """    /* SPDX-License-Identifier: BSD-2-Clause */
    /* AUTOGENRATED CODE DO NOT MODIFY */

    #include <stdlib.h>

    #include "yaml-common.h"
    """
    )
    func = textwrap.dedent(
        """

        TSS2_RC
        Tss2_MU_YAML_{name}_Marshal(
            {name} const *src,
            char            **output)
        {{
            TSS2_RC rc = TSS2_MU_RC_GENERAL_FAILURE;
            yaml_document_t doc = {{ 0 }};
        
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
        
            {name} tmp_dest = {{ 0 }};
        
            key_value parsed_data[] = {{
            {parsers}
            }};
        
            TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
            if (rc != TSS2_RC_SUCCESS) {{
                return rc;
            }}
        
            *dest = tmp_dest;
        
            return TSS2_RC_SUCCESS;
        }}
        """
    )

    type_map = cprsr.get_type_map()

    needed_leaf_functions = {}

    with open(
        os.path.join(proj_root, "src", "tss2-mu-yaml", "yaml-tpms.c"), "w+t"
    ) as f:
        f.write(epilogue)
        f.write("\n")

        for name, type_ in type_map["struct"].items():
            if not (name.startswith("TPMS_") and isinstance(type_, CStruct)):
                continue

            emitters = []
            parsers = []

            field_map = type_.fields
            for field_name, field_type in field_map.items():
                if field_type in type_map["scalar"]:
                    resolved_type = type_to_root(
                        type_map["scalar"], type_map["scalar"][field_type]
                    )
                elif field_type in type_map["struct"]:
                    resolved_type = type_map["struct"][field_type]
                elif field_type in type_map["union"]:
                    resolved_type = type_map["union"][field_type]
                else:
                    raise RuntimeError(f"Unknown type: {field_type}")

                emitters.append(
                    f'    KVP_ADD_MARSHAL("{field_name}", sizeof(src->{field_name}), &src->{field_name}, {resolved_type.name}_generic_marshal)'
                )

                parsers.append(
                    f'    KVP_ADD_UNMARSHAL("{field_name}", sizeof(tmp_dest.{field_name}), &tmp_dest.{field_name}, {resolved_type.name}_generic_unmarshal)'
                )

                if (
                    field_type in type_map["scalar"]
                    and resolved_type.name not in needed_leaf_functions
                ):
                    needed_leaf_functions[resolved_type.name] = [
                        f"{resolved_type.name}_generic_marshal",
                        f"{resolved_type.name}_generic_unmarshal",
                    ]

            emitters = ",\n    ".join(emitters)
            parsers = ",\n    ".join(parsers)

            # emitter list built
            fmt = func.format(emitters=emitters, parsers=parsers, name=name)
            f.write(fmt)

        return needed_leaf_functions


    def generate_leafs(cprsr: CTypeParser, proj_root: str, needed_leafs: dict):


#
# def callable_all_protos():
#     callable_tpm2b_protos()
#     callable_tpms_protos()
#
#
# def callable_all_test_list():
#     callable_tpm2b_test_list()
#     callabale_tpms_simple_test_list()
#
#
# def callable_tpmu_types():
#     for _, obj in inspect.getmembers(tpm2_pytss):
#         if inspect.isclass(obj) and obj.__name__.startswith("TPMU"):
#             print(obj.__name__)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("root")
    args = parser.parse_args()

    proj_root = args.root

    include_file = os.path.join(proj_root, "include", "tss2", "tss2_tpm2_types.h")
    cprsr = CTypeParser(include_file)
    cprsr.parse()

    # generate_simple_tpm2bs(cprsr, proj_root)
    needed_leafs = generate_tpms_code_gen(cprsr, proj_root)

    generate_leafs(cprsr, proj_root, needed_leafs)

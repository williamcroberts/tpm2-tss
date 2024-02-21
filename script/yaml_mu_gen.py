#!/usr/bin/env python3
import argparse
import inspect
import os
import tpm2_pytss
import sys
import textwrap
from tpm2_pytss.types import TPM2B_SIMPLE_OBJECT


def get_subclasses(base_class, package):
    subclasses = []
    for _, obj in inspect.getmembers(package):
        if inspect.isclass(obj) and issubclass(obj, base_class) and obj != base_class:
            subclasses.append(obj)
    return subclasses


def callable_tpm2b_test_protos():
    subclasses = get_subclasses(TPM2B_SIMPLE_OBJECT, package=tpm2_pytss)
    for s in subclasses:
        name = s.__name__
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

def print_proto(name):
    t = textwrap.dedent(
        f"""
        TSS2_RC
        Tss2_MU_YAML_{name}_Marshal(
            {name} const *src,
            char        **yaml);

        TSS2_RC
        Tss2_MU_YAML_{name}_Unmarshal(
            const char *yaml,
            size_t      yaml_len,
            {name}     *dest);
    """
    )

    sys.stdout.write(t)

def callable_tpm2b_protos():
    subclasses = get_subclasses(TPM2B_SIMPLE_OBJECT, package=tpm2_pytss)
    for s in subclasses:
        name = s.__name__
        print_proto(name)


def callable_tpm2b_test_list():
    subclasses = get_subclasses(TPM2B_SIMPLE_OBJECT, package=tpm2_pytss)
    for s in subclasses:
        name = s.__name__
        print(f"cmocka_unit_test(test_{name}_good),")
        print(f"cmocka_unit_test(test_{name}_zero),")
        print(f"cmocka_unit_test(test_{name}_null),")


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

            l.append(obj.__name__)
    return l


def callable_tpms_complex_types():
    simples = get_tpms_simple()
    for _, obj in inspect.getmembers(tpm2_pytss):
        if (
            inspect.isclass(obj)
            and obj.__name__.startswith("TPMS")
            and obj.__name__ not in simples
        ):
            print(obj.__name__)


def callable_tpms_simple_types():
    for s in get_tpms_simple():
        print(s)

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

def callable_all_protos():

    callable_tpm2b_protos()
    callable_tpms_protos()

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

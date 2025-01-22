import "pe"
import "elf"

rule ProgramLanguage_Rust
{
    meta:
        description = "Application written in Rust programming language"
        author = "albertzsigovits"

    strings:
        $commithash = /rustc[\\\/][a-z0-9]{40}[\\\/]library/ ascii wide
        $commitver = /rustc[\\\/][0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}[\\\/]library/ ascii wide

        $trace1 = "RUST_BACKTRACE=1" ascii wide

        $panic1 = "rust_panic" ascii wide
        $panic2 = "panicked at" ascii wide

        $lib1 = /src[\\\/]libcore[\\\/]fmt[\\\/]mod.rs/ ascii wide
        $lib2 = /src[\\\/]libcore[\\\/]slice[\\\/]memchr.rs/ ascii wide
        $lib3 = /src[\\\/]libcore[\\\/]str[\\\/]mod.rs/ ascii wide
        $lib4 = /src[\\\/]libcore[\\\/]unicode[\\\/]printable.rs/ ascii wide
        $lib5 = /src[\\\/]libcore[\\\/]unicode[\\\/]unicode_data.rs/ ascii wide
        $lib6 = /src[\\\/]libcore[\\\/]num[\\\/]mod.rs/ ascii wide

        $mangle = "_ZN" ascii wide

        $src = ".rs" ascii wide

    condition:
        (
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) // MZ
            or (uint32(0) == 0x464c457f) // ELF
        )
        and (
                $commithash
                or $commitver
                or 3 of ($lib*)
                or ($trace1 and 1 of ($panic*))
                or (#mangle > 10 and #src > 5)
        )
}

rule ProgramLanguage_Golang
{
    meta:
        description = "Application written in Golang programming language"
        author = "albertzsigovits"

    strings:
        $func1 = "runtime.main" ascii wide
        $func2 = "main.main" ascii wide
        $func3 = "runtime.gcWork" ascii wide
        $func4 = "runtime.morestack" ascii wide
        $func5 = "runtime.morestack_noctxt" ascii wide
        $func6 = "runtime.newproc" ascii wide
        $func7 = "runtime.gcWriteBarrier" ascii wide
        $func8 = "runtime.Gosched" ascii wide

        $build = " Go buildinf:" ascii wide

        $vendor = "vendor/golang.org" ascii wide

        $skele1 = "main." ascii wide
        $skele2 = "runtime." ascii wide
        $skele3 = "os." ascii wide
        $skele4 = "golang.org" ascii wide

        $sect1 = ".gosymtab" ascii wide
        $sect2 = ".gopclntab" ascii wide
        $sect3 = ".go.buildinfo" ascii wide
        $sect4 = ".note.go.buildid" ascii wide

    condition:
        (
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) // MZ
            or (uint32(0) == 0x464c457f) // ELF
        )
        and (
                4 of ($func*)
                or $build
                or #vendor > 10
                or 4 of ($skele1,$skele2,$skele3,$skele4)
                or 2 of ($sect*)
                or for any i in ( 0 .. pe.number_of_sections ) : (
                    pe.sections[i].name == ".gosymtab"
                    or pe.sections[i].name == ".gopclntab"
                    or pe.sections[i].name == ".go.buildinfo"
                )
                or for any i in ( 0 .. elf.number_of_sections ) : (
                    elf.sections[i].name == ".gosymtab"
                    or elf.sections[i].name == ".gopclntab"
                    or elf.sections[i].name == ".go.buildinfo"
                )
                or pe.pdb_path contains "/go/src/"
        )
}

rule ProgramLanguage_Nim
{
    meta:
        description = "Application written in Nim programming language"
        author = "albertzsigovits"

    strings:
        $sym01 = "io.nim" fullword ascii wide
        $sym02 = "fatal.nim" fullword ascii wide
        $sym03 = "system.nim" fullword ascii wide
        $sym04 = "stdlib_io.nim.c" fullword ascii wide

        $func01 = "_NimMain" fullword ascii wide
        $func02 = "_nimGC_setStackBottom" fullword ascii wide
        $func03 = "_NimMainInner" fullword ascii wide
        $func04 = "_nim_program_result" fullword ascii wide
        $func05 = "_nimAddInt" fullword ascii wide
        $func06 = "_nimSubInt" fullword ascii wide
        $func07 = "_nimCopyMem" fullword ascii wide
        $func08 = "_nimFrame" fullword ascii wide
        $func09 = "_nimCStrLen" fullword ascii wide
        $func10 = "_nimSetMem__systemZmemory_7" fullword ascii wide
        $func11 = "_nimZeroMem" fullword ascii wide
        $func12 = "_nimGCunrefNoCycle" fullword ascii wide
        $func13 = "_nimMulInt" fullword ascii wide
        $func14 = "_nimToCStringConv" fullword ascii wide

        $mod01 = "@NimMainModule@" fullword ascii wide

    condition:
        (
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) // MZ
            or (uint32(0) == 0x464c457f) // ELF
        )
        and (
            6 of them
            or (1 of ($sym*) and 1 of ($func*) and 1 of ($mod*))
        )
}

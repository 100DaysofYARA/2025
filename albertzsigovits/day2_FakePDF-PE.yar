import "pe"
import "hash"

rule IconMismatch_PE_PDF {
    meta:
        description = "Icon mismatch: PE executable with PDF icons"
        author = "albertzsigovits"

    condition:
        uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and (
            hash.sha256(pe.resources[0].offset, pe.resources[0].length) == "0da488a59ce7c34b5362e2c3e900ebaa48c2fa182c183166d290c0c6f10f97c1" // PDF red icon #1
            or hash.sha256(pe.resources[0].offset, pe.resources[0].length) == "42cb714195c0255523313f41629c9d6a123d93f9789f8a8764e52cad405ea199" // PDF red icon #2
            or hash.sha256(pe.resources[0].offset, pe.resources[0].length) == "56cc2dea455f34271b031b51ff2b439a8a8083f4848b5308d4b42c827ba22c1f" // PDF red icon #3
            or hash.sha256(pe.resources[0].offset, pe.resources[0].length) == "683370eb202be9c57e6fe038e4a234c7a4e1f353dfbfe64d8f33397a5a0f0e81" // PDF red icon #4
            or hash.sha256(pe.resources[0].offset, pe.resources[0].length) == "68f1550f74d5cf2a52f1cf3780037facf60a6254e133fcc503a12e1ea5106184" // PDF red icon #5
            or hash.sha256(pe.resources[0].offset, pe.resources[0].length) == "9f12f3b8937665385f43f28caab2ded4469cefbec166d83e57d70e5a7b380067" // PDF red icon #6
            or hash.sha256(pe.resources[0].offset, pe.resources[0].length) == "a27b7e5c64c784418daa27bebb7ffcedbc919649d1a5b6446cd8c02516ba6da6" // PDF red icon #7
            or hash.sha256(pe.resources[0].offset, pe.resources[0].length) == "f7e6bb934282eae0225f37b2d05e81c7bfa95acbf11d1eb9c9662ed3accf5708" // PDF red icon #8
        )
}

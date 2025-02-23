rule ROOT_GET_PSHELL
{
    meta:
        author = "Ian Cook @cioaonk"
        description = "Detects usage of the Get-ReverseShell Powershell tool"
        date = "1/18/2025"
        reference = "https://github.com/gh0x0st/Get-ReverseShell/"

    strings:
        $s1 = "odTPYnuuGIGzrAeHM "
        $pat1 = "(?<!<obfu%)([""''])(?:(?=(\\?))\2.)*?\1(?!%cate>)"
        $s2 = "Invoke-PSObfuscation"
        $s3 = "https://github.com/gh0x0st"


    condition:
        all of them 


}
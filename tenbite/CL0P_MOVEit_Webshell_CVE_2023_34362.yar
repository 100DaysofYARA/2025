rule CL0P_MOVEit_Webshell_CVE_2023_34362 {
    meta:
        author       = "Tenbite Yadetie @https://x.com/BitOfTen"
        date         = "2025-01-17"
        description  = "Detects malicious ASP.NET webshell used by CL0P Ransomware Gang exploiting CVE-2023-34362"
        reference    = "https://gist.github.com/JohnHammond/44ce8556f798b7f6a7574148b679c643"

    strings:
        //HTTP Headers
        $requestHeader1 = "X-siLock-Comment" ascii
        $requestHeader2 = "X-siLock-Step1"   ascii
        $requestHeader3 = "X-siLock-Step2"   ascii
        $requestHeader4 = "X-siLock-Step3"   ascii

        //Azure info
		    $azureData1 = "Response.AppendHeader(\"AzureBlobStorageAccount\", azureAccout);"
        $azureData2 = "Response.AppendHeader(\"AzureBlobKey\", azureBlobKey);"
        $azureData3 = "Response.AppendHeader(\"AzureBlobContainer\", azureBlobContainer);"

        //SQLi
        $sqlQuery1  = "DELETE FROM users WHERE RealName='Health Check Service'" ascii
        $sqlQuery2  = "SELECT Username FROM users WHERE InstID=" ascii

    condition:
(all of ($requestHeader*)) or (all of ($azureData*)) or (all of ($sqlQuery*))

}

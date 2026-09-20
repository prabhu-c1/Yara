rule Lab_Ransom_Note_Test
{
    meta:
        description = "Detects a simulated ransom note used for YARA lab testing"
        author = "Lab"
        purpose = "Testing"

    strings:
        $s1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $s2 = "To recover your files" nocase
        $s3 = "Your personal ID" nocase
        $s4 = "Payment instructions" nocase

    condition:
        3 of ($s*)
}

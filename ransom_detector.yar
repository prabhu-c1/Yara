rule Ransomware_Ransom_Note_Generic
{
    meta:
        description = "Detects likely ransomware ransom notes using common extortion and recovery terminology"
        author = "Prabhu C"
        purpose = "MDR threat hunting"
        confidence = "medium-high"

    strings:

        // Encryption / impact language
        $enc1 = "your network was encrypted" nocase ascii wide
        $enc2 = "your files have been encrypted" nocase ascii wide
        $enc3 = "your files are encrypted" nocase ascii wide
        $enc4 = "your data is encrypted" nocase ascii wide
        $enc5 = "your computers and servers are encrypted" nocase ascii wide
        $enc6 = "encrypted your files" nocase ascii wide
        $enc7 = "all files of importance have been encrypted" nocase ascii wide

        // Data theft / extortion language
        $theft1 = "stolen data" nocase ascii wide
        $theft2 = "stole your corporate data" nocase ascii wide
        $theft3 = "data will be published" nocase ascii wide
        $theft4 = "publish your data" nocase ascii wide
        $theft5 = "sensitive data" nocase ascii wide
        $theft6 = "confidential data" nocase ascii wide
        $theft7 = "downloaded compromising and sensitive data" nocase ascii wide
        $theft8 = "data leak" nocase ascii wide
        $theft9 = "data has been stolen" nocase ascii wide

        // Decryption / recovery language
        $dec1 = "decrypt your files" nocase ascii wide
        $dec2 = "decrypt your data" nocase ascii wide
        $dec3 = "decryption software" nocase ascii wide
        $dec4 = "decryption tool" nocase ascii wide
        $dec5 = "special decryption" nocase ascii wide
        $dec6 = "decryptor" nocase ascii wide
        $dec7 = "recover your files" nocase ascii wide
        $dec8 = "restore your files" nocase ascii wide
        $dec9 = "recover your data" nocase ascii wide
        $dec10 = "restore your data" nocase ascii wide

        // Warnings against recovery
        $warn1 = "don't modify encrypted files" nocase ascii wide
        $warn2 = "do not modify encrypted files" nocase ascii wide
        $warn3 = "don't delete or modify encrypted files" nocase ascii wide
        $warn4 = "do not attempt to decrypt" nocase ascii wide
        $warn5 = "third party software" nocase ascii wide
        $warn6 = "damage your files" nocase ascii wide

        // TOR / communication
        $tor1 = "tor browser" nocase ascii wide
        $tor2 = "torproject.org" nocase ascii wide
        $tor3 = ".onion" nocase ascii wide
        $tor4 = "darknet" nocase ascii wide
        $tor5 = "tox id" nocase ascii wide
        $tor6 = "toxchat" nocase ascii wide

        // Payment / negotiation
        $pay1 = "pay the ransom" nocase ascii wide
        $pay2 = "after payment" nocase ascii wide
        $pay3 = "payment includes" nocase ascii wide
        $pay4 = "bitcoin" nocase ascii wide
        $pay5 = "btc" nocase ascii wide
        $pay6 = "negotiation" nocase ascii wide
        $pay7 = "contact us" nocase ascii wide
        $pay8 = "reach an agreement" nocase ascii wide
        $pay9 = "if you pay" nocase ascii wide

        // Law enforcement / recovery-company discouragement
        $law1 = "police" nocase ascii wide
        $law2 = "FBI" nocase ascii wide
        $law3 = "authorities" nocase ascii wide
        $law4 = "recovery companies" nocase ascii wide
        $law5 = "don't go to the police" nocase ascii wide
        $law6 = "do not inform local authorities" nocase ascii wide

        // Common ransom-note structural terminology
        $common1 = "personal ID" nocase ascii wide
        $common2 = "unique ID" nocase ascii wide
        $common3 = "chat link" nocase ascii wide
        $common4 = "blog link" nocase ascii wide
        $common5 = "our blog" nocase ascii wide

    condition:

        filesize < 2MB and

        (
            // Strong encryption/extortion combination
            (2 of ($enc*) and 1 of ($dec*, $theft*, $tor*, $pay*))

            or

            // Data-theft extortion note
            (2 of ($theft*) and 1 of ($tor*) and 1 of ($pay*, $dec*))

            or

            // Typical ransom instructions
            (1 of ($enc*) and 1 of ($dec*) and 1 of ($tor*) and
             1 of ($pay*, $warn*, $common*))

            or

            // Strong TOR + recovery + negotiation pattern
            (2 of ($tor*) and 1 of ($dec*) and 1 of ($pay*))
        )
}
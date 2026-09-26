rule Ransomware_Ransom_Note_Any_Indicator
{
    meta:
        description = "Detects potential ransomware ransom notes based on common ransom-note terminology"
        author = "Prabhu C"
        purpose = "MDR Threat Hunting"

    strings:

        // Encryption
        $enc01 = "your network was encrypted" nocase ascii wide
        $enc02 = "your files have been encrypted" nocase ascii wide
        $enc03 = "your files are encrypted" nocase ascii wide
        $enc04 = "your data is encrypted" nocase ascii wide
        $enc05 = "your computers and servers are encrypted" nocase ascii wide
        $enc06 = "encrypted your files" nocase ascii wide
        $enc07 = "encrypted all your infrastructure" nocase ascii wide
        $enc08 = "your data is stolen and encrypted" nocase ascii wide

        // Decryption / Recovery
        $dec01 = "decrypt your files" nocase ascii wide
        $dec02 = "decrypt your data" nocase ascii wide
        $dec03 = "decryption software" nocase ascii wide
        $dec04 = "decryption tool" nocase ascii wide
        $dec05 = "special decryption software" nocase ascii wide
        $dec06 = "decryptor" nocase ascii wide
        $dec07 = "recover your files" nocase ascii wide
        $dec08 = "recover your data" nocase ascii wide
        $dec09 = "restore your files" nocase ascii wide
        $dec10 = "restore your data" nocase ascii wide
        $dec11 = "cipher key" nocase ascii wide

        // Data theft / Leak / Extortion
        $ext01 = "stolen data" nocase ascii wide
        $ext02 = "stole your corporate data" nocase ascii wide
        $ext03 = "data will be published" nocase ascii wide
        $ext04 = "publish your data" nocase ascii wide
        $ext05 = "sensitive data" nocase ascii wide
        $ext06 = "confidential data" nocase ascii wide
        $ext07 = "data leak" nocase ascii wide
        $ext08 = "data has been stolen" nocase ascii wide
        $ext09 = "stolen and encrypted" nocase ascii wide
        $ext10 = "stolen files" nocase ascii wide

        // Warnings
        $warn01 = "don't modify encrypted files" nocase ascii wide
        $warn02 = "do not modify encrypted files" nocase ascii wide
        $warn03 = "don't delete or modify encrypted files" nocase ascii wide
        $warn04 = "do not attempt to decrypt" nocase ascii wide
        $warn05 = "third party software" nocase ascii wide
        $warn06 = "damage your files" nocase ascii wide
        $warn07 = "don't try to decrypt" nocase ascii wide

        // TOR / Darknet / Communication
        $tor01 = "tor browser" nocase ascii wide
        $tor02 = "torproject.org/download" nocase ascii wide
        $tor03 = ".onion" nocase ascii wide
        $tor04 = "darknet" nocase ascii wide
        $tor05 = "tox id" nocase ascii wide
        $tor06 = "toxchat" nocase ascii wide
        $tor07 = "chat link" nocase ascii wide
        $tor08 = "blog link" nocase ascii wide

        // Payment / Negotiation
        $pay01 = "pay the ransom" nocase ascii wide
        $pay02 = "after payment" nocase ascii wide
        $pay03 = "payment includes" nocase ascii wide
        $pay04 = "bitcoin" nocase ascii wide
        $pay05 = "btc" nocase ascii wide
        $pay06 = "negotiation" nocase ascii wide
        $pay07 = "reach an agreement" nocase ascii wide
        $pay08 = "if you pay" nocase ascii wide

        // Victim identification / contact
        $id01 = "personal ID" nocase ascii wide
        $id02 = "unique ID" nocase ascii wide
        $id03 = "OrganizationID" nocase ascii wide
        $id04 = "authorization code" nocase ascii wide

    condition:
        filesize < 2MB and any of them
}
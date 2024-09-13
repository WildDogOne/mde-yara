rule TestScan : TestScan
{
    meta:
        description = "This is just an example"
        threat_level = 3
        in_the_wild = true

    strings:
        $a = "c.1td.eu"

    condition:
        $a
}
from arcount.devtype import guess


def test_specialist_makers_are_confident():
    assert guess("Hangzhou Hikvision Digital Technology Co.,Ltd.") == "camera"
    assert guess("Dahua Technology") == "camera"
    assert guess("Seiko Epson Corporation") == "printer"
    assert guess("Nintendo Co.,Ltd") == "game console"
    assert guess("Espressif Inc.") == "smart home / IoT"
    assert guess("TP-LINK TECHNOLOGIES CO.,LTD.") == "router / network gear"
    assert guess("Synology Incorporated") == "NAS / storage"


def test_big_makers_get_a_list_with_a_question_mark():
    assert guess("Apple, Inc.").endswith("?") and "iPhone" in guess("Apple, Inc.")
    assert guess("Samsung Electronics Co.,Ltd").endswith("?")
    assert guess("Intel Corporate").endswith("?")


def test_whole_words_only_and_unknown_is_blank():
    assert guess("Engineering Ringo Ltd") == ""        # "ring" must not match inside words
    assert guess("Ring LLC") == "camera"
    assert guess("Some Unknown Vendor GmbH") == ""
    assert guess("", "00:11:22:33:44:55") == ""


def test_address_based_guesses():
    assert guess("", "02:aa:bb:cc:00:01") == "phone / laptop (random MAC)"
    assert guess("PCS Systems AG", "08:00:27:aa:bb:cc") == "virtual machine (VirtualBox)"
    assert guess("Anything", "02:aa:bb:cc:00:01", is_gateway=True) == "gateway / router"

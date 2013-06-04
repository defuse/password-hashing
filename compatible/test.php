<?php

    require_once('PasswordHash.php');
    $hash = create_hash("foobar");
    $result = validate_password("foobar", $hash);
    if ($result)
    {
        echo "Good";
    }
    else
    {
        echo "Bad";
    }

    $result = validate_password("barfoo", $hash);
    if ($result)
    {
        echo "Bad";
    }
    else
    {
        echo "Good";
    }

    echo "\n";

    echo $hash;

?>

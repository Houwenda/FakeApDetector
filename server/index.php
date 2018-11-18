<?php
  if(!isset($_GET['action'])) {
    die();
  } else if($_GET['action'] == 'upload'){
    $allowedExts = array("pcapng");
    $temp = explode(".", $_FILES["file"]["name"]);
    $extension = end($temp);
    if ((($_FILES["file"]["type"] == "application/octet-stream"))
    && ($_FILES["file"]["size"] < 409600)
    && in_array($extension, $allowedExts))
    {
        if ($_FILES["file"]["error"] > 0){
          echo "error: ".$_FILES["file"]["error"];
        }
        else
        {
            if (file_exists("upload/" . $_FILES["file"]["name"])){
              echo "file exists";
            }
            else
            {
                move_uploaded_file($_FILES["file"]["tmp_name"], "upload/" . $_FILES["file"]["name"]);
            }
        }
    }
    else{
      echo "invalid file type";
    }
    exec("python analysis.py upload/".$_FILES["file"]["name"],$result);
    print_r($result);
  }

?>

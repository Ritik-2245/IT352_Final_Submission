<html>
  <head>
   
    <title>CommandExec</title>
  </head>
  <body>
    <div style="background-color:#afafaf;padding:15px;border-radius:20px 20px 0px 0px">
      <button type="button" name="homeButton" onclick="location.href='../homepage.html';">Home Page</button>
    </div>
    <div style="background-color:#c9c9c9;padding:20px;">
      <h1 align="center">Browse The Files!</h1>
    <form align="center" action='index.php' method="$_GET">
      What's it:
      <input type="text" name="typeBox" value=""><br>
      <input type="submit" value="Submit">
    </form>
  </div>
  <div style="background-color:#ecf2d0;padding:20px;border-radius:0px 0px 20px 20px" align="center">
    <?php
    if(!file_exists(".hidden")){
      mkdir(".hidden");
      exec("echo \"flag:secret\" > .hidden/log4.txt");
      if(strtoupper(substr(PHP_OS, 0, 3)) === 'WIN'){
        exec("attrib +h .hidden");
      }
    }
   
    if(isset($_GET["typeBox"])){
      $target =$_GET["typeBox"];
      $substitutions = array(
        '&&'=>'',
        '& ' => '',
        '&& ' => '',
        ';'  => '',
        '|' => '',
        '-'  => '',
        '$'  => '',
        '('  => '',
        ')'  => '',
        '`'  => '',
        '||' => ''
      );
      $target = str_replace(array_keys($substitutions),$substitutions,$target);
      echo shell_exec($target);
      if($_GET["typeBox"] == $target)
        echo "input was normal";
      else
        echo "input was not malicious";
    }

    ?>
  </div>
  </body>
</html>

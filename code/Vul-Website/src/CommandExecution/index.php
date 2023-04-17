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
   
   
    if(isset($_GET["typeBox"])){
  
     $target =$_GET["typeBox"];
      echo shell_exec($target);
    
    }
    ?>
  </div>
  </body>
</html>

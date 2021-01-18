toggleBtn = function(){
    var btn = document.getElementsByClassName("fort-loginBtn")[0];
    btn.style.display = "none";
    var btn = document.getElementById("fort-loginBtnAlt");
    btn.style.display = "block";
}

var urlString = window.location.href; 
var paramString = urlString.split("#")[1]; 
var paramsArr = paramString.split("&"); 

for (var i = 0; i < paramsArr.length; i++) { 
    var pair = paramsArr[i].split("=");
    if ( pair[0] == "uninitialized" && pair[1] == "true" ) {
        document.getElementById("fort-warning").innerHTML = "Welcome and please set a new password!";
        document.getElementById("fort-warning").parentNode.classList.add("fort-red");
        document.getElementById("fort-loginRePass").style.display = "flex";
        document.getElementById("fort-loginBtnMain").disabled = true;	
    }
    if ( pair[0] == "failure" && pair[1] == "credentials" ) {
        document.getElementById("fort-warning").innerHTML = "Incorrect password. Please try again!";
        document.getElementById("fort-warning").parentNode.classList.add("fort-red");	
    }
    if ( pair[0] == "failure" && pair[1] == "input" ) {
        document.getElementById("fort-warning").innerHTML = "Something went wrong. Please try again!";
        document.getElementById("fort-warning").parentNode.classList.add("fort-red");	
    }
}

checkInput = function(){
    var firstInput = document.getElementById("inputPassword").value;
    var secondInput = document.getElementById("inputRePassword").value;

    if (firstInput === secondInput) {
        // do something here if inputs are same
        document.getElementById("fort-info").style.display = "none";
        console.log("Good to go!");
        document.getElementById("fort-loginBtnMain").disabled = false;
    } else if (firstInput > secondInput) {
        document.getElementById("fort-loginBtnMain").disabled = true;
        document.getElementById("fort-info").style.display = "flex";
        
    } else {
        document.getElementById("fort-loginBtnMain").disabled = true;
        document.getElementById("fort-info").style.display = "flex";
    }
}
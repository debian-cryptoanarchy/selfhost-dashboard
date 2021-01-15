var path = window.location.pathname;
var idx = path.indexOf('/', 1);
if(idx < 0) {
    root_path = path;
} else {
    root_path = path.substr(0, idx);
}
console.log(root_path);

var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState === 4) {
        var response = JSON.parse(xhr.responseText);
        console.log(response);
        var apps_html = ""
        for (app of response.apps) {
            console.log(app);
            apps_html += "<div class=\"col-sm-2\"><div class=\"card fort-tile\"><a href=\""+ app.url +"\" target=\"_blank\"><img src=\""+ app.icon +"\" class=\"fort-tileImg float-left\" alt=\"\"></a><h5 class=\"card-title\"><a class=\"fort-tileName text-break text-center\"  target=\"_blank\" href=\""+ app.url +"\">"+app.name+"</a></h5></div></div>"
        }
        document.getElementById("apps").innerHTML = apps_html;
    }
}
xhr.open('GET', root_path + '/apps');
xhr.send()
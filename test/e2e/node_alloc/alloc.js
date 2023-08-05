let array = [];
let start = Date.now();
var i = setInterval(function() {
        if (Date.now() - start > 10000)
                clearInterval(i);
        array.push(new Array(1000000).join("x"));
}, 1000);

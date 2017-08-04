Java.perform(function(){
    var classes = Java.enumerateLoadedClassesSync();

    for(var i = 0; i < classes.length; i++)
    {
        if(classes[i].toString().toLowerCase().indexOf("%s".toLowerCase()) != -1)
        {
            send(classes[i].toString());
        }
    }
});


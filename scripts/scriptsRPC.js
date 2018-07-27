'use strict';

rpc.exports = {
    // getClasses that containsThis
    getclasses: function(containsThis) {
        Java.perform(function() {
            send("[*] Enumerating classes...");
            Java.enumerateLoadedClasses({
                onMatch: function(entry) {
                    if (entry.toString().toLowerCase().search(containsThis.toLowerCase()) != -1) {
                        send(entry.toString());
                    }
                },
                onComplete: function (){
                    send("[*] Done!");
                }
            });
        });
    },

    // Search Methods in all classes
    searchmethod: function(methodToSearch){
        Java.perform(function(){
            send("[*] Searching for " + methodToSearch);
            send("[*] This can take some time...");

            Java.enumerateLoadedClasses({
                onMatch: function(entry) {
                    try{
                        var classX = Java.use(entry.toString());
                    } catch(err){
                        send("[!] Class not found: " + entry.toString());
                        return;
                    }

                    var methods = classX.class.getDeclaredMethods();

                    for(var j = 0; j < methods.length; j++){
                        var methodName = methods[j].toGenericString();

                        if(methodName.toLowerCase().search(methodToSearch.toLowerCase()) != -1){
                            send("[*] FOUND HERE - " + classX.toString());
                        }
                    }
                },
                onComplete: function (){
                    send("[*] Done!");
                }
            });
        });
    },

    getmethods: function(nameOfClass, containsThis){
        Java.perform(function(){
            try{
                var className = Java.use(nameOfClass);
            } catch(err){
                send("[!] Class not found: " + nameOfClass);
                return;
            }

            var methods = className.class.getDeclaredMethods();

            for(var i = 0; i < methods.length; i++)
            {
                var methodSignature = methods[i].toGenericString();

                if (methodSignature.toString().toLowerCase().search(containsThis.toLowerCase()) == -1) {
                    continue;
                }
                var initParenthesis = 0;
                while(methodSignature[initParenthesis] != '(')
                {
                    initParenthesis++;
                }

                var endParenthesis = methodSignature.length - 1;
                while(methodSignature[endParenthesis] != ')')
                {
                    endParenthesis--;
                }

                var methodFullNameTmp = methodSignature.slice(0, initParenthesis).split(' ');
                var methodFullName = methodFullNameTmp[methodFullNameTmp.length - 1];
                
                var methodShortNameTmp = methodFullName.split('.')
                var methodShortName = methodShortNameTmp[methodShortNameTmp.length - 1];
                
                j = initParenthesis;
                while(methodSignature[j] != ' ' && j >= 0)
                {
                    j--;
                }

                var newMethodSignature = methodSignature.slice(0, j) + ' ' + methodShortName;

                var args = methodSignature.slice(initParenthesis + 1, endParenthesis).split(',');
                
                newMethodSignature += '(';

                for(var j = 0; j < args.length; j++)
                {
                    var newArgumentNameList = args[j].split('.');
                    var newArgumentName = newArgumentNameList[newArgumentNameList.length - 1];

                    newMethodSignature += newArgumentName;
                    if(j != args.length-1){
                        newMethodSignature += ', ';
                    }
                }

                newMethodSignature += ')';

                send(newMethodSignature);
            }
        });
    }
};


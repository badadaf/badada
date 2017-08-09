'use strict';

rpc.exports = {
    // getClasses that containsThis
    getclasses: function(containsThis) {
        Java.perform(function() {
            var classes = Java.enumerateLoadedClassesSync();

            for (var i = 0; i < classes.length; i++) {
                //if (classes[i].toString().toLowerCase().indexOf(containsThis.toLowerCase()) != -1) {
                if (classes[i].toString().toLowerCase().search(containsThis.toLowerCase()) != -1) {
                    send(classes[i].toString());
                }
            }
        });
    },
    // Search Methods
    searchmethod: function(methodToSearch){
        Java.perform(function(){
            send("Searching for " + methodToSearch);
            var classes = Java.enumerateLoadedClassesSync();
            
            for(var i = 0; i < classes.length; i++){
                var classX = Java.use(classes[i].toString());

                var methods = classX.class.getDeclaredMethods();
                
                for(var j = 0; j < methods.length; j++){
                    var methodName = methods[j].getName();

                    if(methodName.indexOf(methodToSearch) != -1){
                        send(classX.toString());
                    }
                }
            }
        });
    },

    getmethods: function(nameOfClass, containsThis){
        Java.perform(function(){
            var className = Java.use(nameOfClass);

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


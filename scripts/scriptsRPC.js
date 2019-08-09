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
                            send("[*] FOUND HERE - " + classX.toString() + " : " + methodName);
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
    },

    generatehooks: function(classFullPathName, methodNameFilter){
        Java.perform(function(){
            try{
                var Clazz = Java.use(classFullPathName);
            } catch(err){
                send('ERROR: Class not found: ' + classFullPathName);
                return;
            }

            var classFullPathNameSplitted = classFullPathName.split('.');
            var className = classFullPathNameSplitted[classFullPathNameSplitted.length - 1];
            var classNiceName = className.replace(new RegExp('\\$', 'g'), '_');

            var scriptString = 'Java.perform(function(){\n';
            scriptString += '\tvar ' + classNiceName + ' = Java.use("' + classFullPathName + '");\n\n';

            var ClazzMethods = Clazz.class.getDeclaredMethods();
            var methodNameCount = {};

            for(var i = 0; i < ClazzMethods.length; i++){
                var methodFullSignature = ClazzMethods[i].toGenericString();

                var lastMarkIndex = -1;
                for(var j = 0; methodFullSignature[j] != '('; j++){
                    if(methodFullSignature[j] == ' ' || methodFullSignature[j] == '.'){
                        lastMarkIndex = j;
                    }
                }

                var methodName = methodFullSignature.slice(lastMarkIndex+1, j);

                if(methodNameFilter !== "" && methodName.toLowerCase().indexOf(methodNameFilter.toLowerCase()) === -1){
                    continue;
                }

                if(!(methodName in methodNameCount)){
                    methodNameCount[methodName] = 1;
                    var overloads = Clazz[methodName].overloads;

                    overloads.forEach(function(overload){
                        var argTypes = overload.argumentTypes;

                        scriptString += "\t//Method Signature => " + overload.returnType.className + " " + overload.methodName + "(" + overload.argumentTypes.map(function(type){ return type.className }).join(", ") + ")\n";
                        scriptString += '\t//' + classNiceName + '.' + methodName;

                        if(overloads.length > 1){
                            scriptString += '.overload(';

                            for(var j = 0; j < argTypes.length; j++){
                                if(j == argTypes.length - 1){
                                    scriptString += "'" + argTypes[j].className + "'";

                                }
                                else{
                                    scriptString += "'" + argTypes[j].className + "', ";
                                }
                            }

                            scriptString += ')';
                        }

                        scriptString += '.implementation = function(';

                        for(var j = 0; j < argTypes.length; j++){
                            if(j == argTypes.length - 1){
                                scriptString += 'p' + (j+1).toString();
                            }
                            else{
                                scriptString += 'p' + (j+1).toString() + ', ';
                            }
                        }

                        scriptString += '){\n';
                        scriptString += '\t//\tsend("Entering ' + classNiceName + "." + methodName + '");\n';
                        scriptString += '\t//\tvar originalResult = this.' + methodName + '(';

                        for(var j = 0; j < argTypes.length; j++){
                            if(j == argTypes.length - 1){
                                scriptString += 'p' + (j+1).toString();
                            }
                            else{
                                scriptString += 'p' + (j+1).toString() + ', ';
                            }
                        }

                        scriptString += ');\n';
                        scriptString += '\t//\tsend("Leaving ' + classNiceName + "." + methodName + '");\n';
                        scriptString += '\t//\treturn originalResult;\n';
                        scriptString += '\t//};\n\n';
                    });
                }
            }

            scriptString += '\n});'

            var finalScriptString = scriptString.replace(new RegExp('\t', 'g'), '    ');

            send(finalScriptString);
        });
    }
};


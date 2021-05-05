'use strict';

rpc.exports = {
    // getClasses that containsThis
    getclasses: function(containsThis, shouldIntrospect) {
        Java.perform(function() {
            send("[*] Enumerating classes...");
            var shouldStopFlag = false;
            var auxCount = 0;

            Java.enumerateLoadedClasses({
                onMatch: function(entry) {
                    auxCount += 1
                    if(shouldStopFlag == false && auxCount % 1000 == 0) {
                        send('shouldStopSyncMsg');
                        var op = recv('shouldStopSyncMsg', function(value) {
                            shouldStopFlag = value.payload;
                        });

                        op.wait();
                    }

                    if(shouldStopFlag) {
                        return 'stop';
                    }

                    if (entry.toString().toLowerCase().search(containsThis.toLowerCase()) != -1) {
                        var message = entry.toString();

                        if(shouldIntrospect) {
                            try{
                                var Clazz = Java.use(entry);

                                if(Clazz != null) {
                                    var fields = Clazz.class.getDeclaredFields();

                                    if(fields != null) {
                                        message += " -> [introspect]:\n";

                                        for(var i = 0; i < fields.length; i++){
                                            var f = fields[i];

                                            if(f == null) {
                                                continue;
                                            }

                                            var accessible = f.isAccessible();
                                            f.setAccessible(true);

                                            var value = null;

                                            try {
                                                value = f.get(null)
                                            } catch(err) {
                                            }

                                            message += "\t" + f.getName() + ': ' + value + "\n";

                                            f.setAccessible(accessible);
                                        }
                                    }
                                }

                            } catch(err) {
                                message += "error while introspecting: " + err;
                            }
                        }

                        send(message)
                    }
                },
                onComplete: function (){
                    if(shouldStopFlag) {
                        send('stoppedSyncMsg');
                        shouldStopFlag = false;
                        return;
                    }

                    send("[*] Done!");
                }
            });
        });
    },

    // getObjects with exact name "className"
    getobjects: function(className, hashCodeFilter) {
        Java.perform(function() {
            send("[*] Enumerating " + className + " objects...");
            var shouldStopFlag = false;
            var auxCount = 0;
            var output = '';

            try {
                var clazz = Java.use(className);
            } catch(e) {
                send("[-] Class " + className + " not found. Aborting\n");
                return;
            }

            Java.choose(className, {
                onMatch: function(instance) {
                    if(hashCodeFilter != '' && instance.hashCode() != hashCodeFilter) {
                        return;
                    }

                    auxCount += 1
                    if(shouldStopFlag == false && auxCount % 100 == 0) {
                        send('shouldStopSyncMsg');
                        var op = recv('shouldStopSyncMsg', function(value) {
                            shouldStopFlag = value.payload;
                        });

                        op.wait();
                    }

                    if(shouldStopFlag) {
                        return 'stop';
                    }

                    var fields = Object.getOwnPropertyNames(instance);
                    var message = 'Listing object[hashCode:' + instance.hashCode() + "] attributes:\n";

                    fields = fields.sort();
                    for(var i = 0; i < fields.length; i++) {
                        var field = fields[i];

                        if(field == 'shadow$_klass_' || field == 'shadow$_monitor_') {
                            continue;
                        }
                        else if(typeof instance[field] === 'object') {
                            var attributeValue = instance[field].value;

                            message += "\t" + field + ': ' + attributeValue + "\n";
                        }
                    }

                    send(message);
                },
                onComplete: function (){
                    if(shouldStopFlag) {
                        send('stoppedSyncMsg');
                        shouldStopFlag = false;
                        return;
                    }

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

            var shouldStopFlag = false;
            var auxCount = 0;

            Java.enumerateLoadedClasses({
                onMatch: function(entry) {
                    auxCount += 1
                    if(shouldStopFlag == false && auxCount % 50 == 0) {
                        send('shouldStopSyncMsg');
                        var op = recv('shouldStopSyncMsg', function(value) {
                            shouldStopFlag = value.payload;
                        });

                        op.wait();
                    }

                    if(shouldStopFlag) {
                        return 'stop';
                    }

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
                    if(shouldStopFlag) {
                        send('stoppedSyncMsg');
                        shouldStopFlag = false;
                        return;
                    }

                    send("[*] Done!");
                }
            });
        });
    },

    getmethods: function(nameOfClass, containsThis){
        Java.perform(function(){
            var shouldStopFlag = false;
            var auxCount = 0;

            try{
                var className = Java.use(nameOfClass);
            } catch(err){
                send("[!] Class not found: " + nameOfClass);
                return;
            }

            var methods = className.class.getDeclaredMethods();

            for(var i = 0; i < methods.length; i++)
            {
                auxCount += 1;
                if(shouldStopFlag == false && auxCount % 10 == 0) {
                    send('shouldStopSyncMsg');
                    var op = recv('shouldStopSyncMsg', function(value) {
                        shouldStopFlag = value.payload;
                    });

                    op.wait();
                }

                if(shouldStopFlag) {
                    send('stoppedSyncMsg');
                    shouldStopFlag = false;
                    return;
                }

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
            var shouldStopFlag = false;
            var auxCount = 0;

            try{
                var Clazz = Java.use(classFullPathName);
            } catch(err){
                send('ERROR: Class not found: ' + classFullPathName);
                return;
            }

            var classFullPathNameSplitted = classFullPathName.split('.');
            var className = classFullPathNameSplitted[classFullPathNameSplitted.length - 1];
            var classNiceName = className.replace(new RegExp('\\$', 'g'), '_').replace('-', '_');

            var scriptString = 'Java.perform(function(){\n';
            scriptString += '\tvar ' + classNiceName + ' = Java.use("' + classFullPathName + '");\n\n';

            var ClazzConstructors = Clazz.class.getDeclaredConstructors();
            var methodNameCount = {};

            for(var i = 0; i < ClazzConstructors.length; i++){
                auxCount += 1;
                if(shouldStopFlag == false && auxCount % 10 == 0) {
                    send('shouldStopSyncMsg');
                    var op = recv('shouldStopSyncMsg', function(value) {
                        shouldStopFlag = value.payload;
                    });

                    op.wait();
                }

                if(shouldStopFlag) {
                    send('stoppedSyncMsg');
                    shouldStopFlag = false;
                    return;
                }

                var constructorFullSignature = ClazzConstructors[i].toGenericString();

                var lastMarkIndex = -1;
                for(var j = 0; constructorFullSignature[j] != '('; j++){
                    if(constructorFullSignature[j] == ' ' || constructorFullSignature[j] == '.'){
                        lastMarkIndex = j;
                    }
                }

                var constructorName = constructorFullSignature.slice(lastMarkIndex+1, j);

                if(methodNameFilter !== "" && "init".indexOf(methodNameFilter.toLowerCase()) === -1){
                    continue;
                }

                if(!(constructorName in methodNameCount)){
                    methodNameCount[constructorName] = 1;
                    var overloads = Clazz["$init"].overloads;

                    overloads.forEach(function(overload){
                        var argTypes = overload.argumentTypes;

                        scriptString += "\t//Constructor Signature => " + overload.returnType.className + " " + overload.methodName + "(" + overload.argumentTypes.map(function(type){ return type.className }).join(", ") + ")\n";
                        scriptString += '\t' + classNiceName + "['$init']";

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
                        scriptString += "\t\tvar originalResult = this['" + "$init']" + '(';

                        for(var j = 0; j < argTypes.length; j++){
                            if(j == argTypes.length - 1){
                                scriptString += 'p' + (j+1).toString();
                            }
                            else{
                                scriptString += 'p' + (j+1).toString() + ', ';
                            }
                        }

                        scriptString += ');\n\n';

                        if(argTypes.length > 0){
                            scriptString += '\t\tsend("';

                            scriptString += classNiceName + "." + '$init params: " + ';

                            for(var j = 0; j < argTypes.length; j++){
                                if(j == argTypes.length - 1){
                                    scriptString += '"p' + (j+1).toString() + '=" + p' + (j+1).toString();
                                }
                                else{
                                    scriptString += '"p' + (j+1).toString() + '=" + p' + (j+1).toString() + ' + ", " + ';
                                }
                            }

                            scriptString += ');\n\n';
                        }
                        else{
                            scriptString += '\t\tsend("';
                            scriptString += classNiceName + "." + '$init called. There are no params.");\n\n';
                        }

                        scriptString += '\t\treturn originalResult;\n';
                        scriptString += '\t};\n\n';
                    });
                }
            }

            var ClazzMethods = Clazz.class.getDeclaredMethods();
            methodNameCount = {};

            auxCount = 0;
            for(var i = 0; i < ClazzMethods.length; i++){
                auxCount += 1;
                if(shouldStopFlag == false && auxCount % 10 == 0) {
                    send('shouldStopSyncMsg');
                    var op = recv('shouldStopSyncMsg', function(value) {
                        shouldStopFlag = value.payload;
                    });

                    op.wait();
                }

                if(shouldStopFlag) {
                    send('stoppedSyncMsg');
                    shouldStopFlag = false;
                    return;
                }

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
                        scriptString += '\t' + classNiceName + "['" + methodName + "']";

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
                        scriptString += "\t\tvar originalResult = this['" + methodName + "'](";

                        for(var j = 0; j < argTypes.length; j++){
                            if(j == argTypes.length - 1){
                                scriptString += 'p' + (j+1).toString();
                            }
                            else{
                                scriptString += 'p' + (j+1).toString() + ', ';
                            }
                        }

                        scriptString += ');\n\n';

                        if(argTypes.length > 0) {
                            scriptString += '\t\tsend("';

                            scriptString += classNiceName + "." + methodName + ' params: " + ';

                            for(var j = 0; j < argTypes.length; j++){
                                if(j == argTypes.length - 1){
                                    scriptString += '"p' + (j+1).toString() + '=" + p' + (j+1).toString();
                                }
                                else{
                                    scriptString += '"p' + (j+1).toString() + '=" + p' + (j+1).toString() + ' + ", " + ';
                                }
                            }

                            scriptString += ');\n\n';
                        }
                        else{
                            scriptString += '\t\tsend("';
                            scriptString += classNiceName + "." + methodName + ' called. There are no params.");\n\n';
                        }


                        scriptString += '\t\treturn originalResult;\n';
                        scriptString += '\t};\n\n';
                    });
                }
            }
            scriptString += '\n});'

            var finalScriptString = scriptString.replace(new RegExp('\t', 'g'), '    ');

            if(shouldStopFlag == false) {
                send('shouldStopSyncMsg');
                var op = recv('shouldStopSyncMsg', function(value) {
                    shouldStopFlag = value.payload;
                });

                op.wait();
            }

            if(shouldStopFlag) {
                send('stoppedSyncMsg');
                shouldStopFlag = false;
                return;
            }

            send(finalScriptString);
        });
    }
};


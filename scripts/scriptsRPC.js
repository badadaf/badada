'use strict';

function getClassFromAnyClassLoader(className) {
    var clazz = null;

    try {
        clazz = Java.use(className);
        return clazz;
    }
    catch(error) {
        var classLoaders = Java.enumerateClassLoadersSync();

        for(var i = 0; i < classLoaders.length; i++) {
            try {
                var classFactory = Java.ClassFactory.get(classLoaders[i]);
                clazz = classFactory.use(className);
                return clazz;
            }
            catch(error) {}
        }
    }

    throw new Error("Couldn't find the class '" + className + "' in any class loader");
}

function getAnyClassFactoryFor(className) {
    var clazz = null;

    try {
        clazz = Java.use(className);
        return Java.ClassFactory.get(Java.classFactory.loader);
    }
    catch(error) {
        var classLoaders = Java.enumerateClassLoadersSync();

        for(var i = 0; i < classLoaders.length; i++) {
            try {
                var classFactory = Java.ClassFactory.get(classLoaders[i]);
                clazz = classFactory.use(className);
                return classFactory;
            }
            catch(error) {}
        }
    }

    throw new Error("Couldn't find the class factory for '" + className + "'");
}

rpc.exports = {
    // getClasses that containsThis - it searchs in all APK classes and in all loaded classes
    getclasses: function(containsThis, shouldIntrospect) {
        var alreadySent = [];

        Java.perform(function(){
            send('[*] Enumerating all classes in APK file...')
            try {
                var activityThread = Java.use('android.app.ActivityThread');
                var currentApplication = activityThread.currentApplication();
                var context = currentApplication.getApplicationContext();
                var appInfo = context.getPackageManager().getApplicationInfo(context.getPackageName(), 0);
                var apkFilePath = appInfo.publicSourceDir.value;
                var classFile = Java.openClassFile(apkFilePath);
                var classNames = classFile.getClassNames();

                for(var i = 0; i < classNames.length; i++) {
                    if (classNames[i].toString().toLowerCase().search(containsThis.toLowerCase()) != -1) {
                        var message = classNames[i].toString();

                        if(shouldIntrospect) {
                            try{
                                var Clazz = getClassFromAnyClassLoader(classNames[i].toString());

                                if(Clazz != null) {
                                    var fields = Clazz.class.getDeclaredFields();

                                    if(fields != null) {
                                        message += " -> [introspect]:\n";

                                        for(var j = 0; j < fields.length; j++){
                                            var f = fields[j];

                                            if(f == null) {
                                                continue;
                                            }

                                            var accessible = f.isAccessible();
                                            f.setAccessible(true);

                                            var value = null;

                                            try {
                                                value = f.get(null)
                                                value = value.toString();
                                            } catch(err) {
                                            }

                                            message += "\t" + f.getName() + ': ' + JSON.stringify(value) + "\n";

                                            f.setAccessible(accessible);
                                        }
                                    }
                                }

                            } catch(err) {
                                message += "error while introspecting: " + err;
                            }
                        }
                        
                        if(!alreadySent.includes(message)){
                            send(message);
                            alreadySent.push(message);
                        }
                    }
                }
            } catch(err){
                send('Error: ' + err);
            }
        });

        Java.perform(function() {
            send("\n\n[*] Enumerating remaining loaded classes...");
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
                                var Clazz = getClassFromAnyClassLoader(entry);

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
                                                value = value.toString();
                                            } catch(err) {
                                            }

                                            message += "\t" + f.getName() + ': ' + JSON.stringify(value) + "\n";

                                            f.setAccessible(accessible);
                                        }
                                    }
                                }

                            } catch(err) {
                                message += "error while introspecting: " + err;
                            }
                        }

                        if(!alreadySent.includes(message)){
                            send(message);
                            alreadySent.push(message);
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

    // getObjects with exact name "className"
    getobjects: function(className, hashCodeFilter) {
        Java.perform(function() {
            send("[*] Enumerating " + className + " objects...");
            var shouldStopFlag = false;
            var auxCount = 0;
            var output = '';

            try {
                var clazz = getClassFromAnyClassLoader(className);
            } catch(e) {
                send("[-] Class " + className + " not found. Aborting\n");
                return;
            }

            var classFactory = getAnyClassFactoryFor(className);

            classFactory.choose(className, {
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

                            message += "\t" + JSON.stringify(field) + ': ' + JSON.stringify(attributeValue) + "\n";
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
                        var classX = getClassFromAnyClassLoader(entry.toString());
                    } catch(err){
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
                var className = getClassFromAnyClassLoader(nameOfClass);
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
        const returnValue = "test";
        return new Promise((resolve, reject) => {
            Java.perform(function(){
                try {
                    var shouldStopFlag = false;
                    var auxCount = 0;

                    try{
                        var Clazz = getClassFromAnyClassLoader(classFullPathName);
                    } catch(err){
                        send('ERROR: Class not found: ' + classFullPathName);
                        return;
                    }

                    var classFullPathNameSplitted = classFullPathName.split('.');
                    var className = classFullPathNameSplitted[classFullPathNameSplitted.length - 1];
                    var classNiceName = className.replace(new RegExp('\\$', 'g'), '_').replace('-', '_');

                    var scriptString = 'Java.perform(function(){\n';
                    scriptString += '\tfunction getClassFromAnyClassLoader(className) {\n\t\tvar clazz = null;\n\n\t\ttry {\n';
                    scriptString += '\t\t\tclazz = Java.use(className);\n\t\t\treturn clazz;\n\t\t}\n\t\tcatch(error) {\n\t\t\tvar classLoaders = Java.enumerateClassLoadersSync();\n';
                    scriptString += '\t\t\tfor(var i = 0; i < classLoaders.length; i++) {\n\t\t\t\ttry {\n\t\t\t\t\tvar classFactory = Java.ClassFactory.get(classLoaders[i]);\n';
                    scriptString += '\t\t\t\t\tclazz = classFactory.use(className);\n\t\t\t\t\treturn clazz;\n\t\t\t\t}\n\t\t\t\tcatch(error) {}\n\t\t\t}\n\t\t}\n';
                    scriptString += '\t\tthrow new Error("Could not find the class " + className + " in any class loader");\n\t}\n\n';

                    scriptString += '\tfunction printStackTrace() {\n\t\tvar Exception = Java.use("java.lang.Exception");\n\n\t\tvar stackTrace = Exception.$new().getStackTrace();';
                    scriptString += '\n\t\tconsole.log("[*] Stack Trace:");\n\n\t\tfor (var i = 0; i < stackTrace.length; i++) {\n\t\t\tconsole.log("\t" + stackTrace[i].toString());\n\t\t}\n\t}\n\n'



                    scriptString += '\tvar ' + classNiceName + ' = getClassFromAnyClassLoader("' + classFullPathName + '");\n\n';

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

                            var overloads = [];

                            try {
                                overloads = Clazz["$init"].overloads;
                            }
                            catch(err) {
                                send('[!] Failed to hook ' + classNiceName + "['$init']");
                            }

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

                            var overloads = [];

                            try {
                                overloads = Clazz[methodName].overloads;
                            }
                            catch(err) {
                                send('[!] Failed to hook ' + classNiceName + "['" + methodName + "']");
                            }

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

                    resolve(finalScriptString)
                } catch (error) {
                    console.error("Error in generatehooks:", error);
                    reject(error);
                }


            });
        });
    }
};
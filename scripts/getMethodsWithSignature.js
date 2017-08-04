Java.perform(function(){
    var className = Java.use("%s");

    var methods = className.class.getDeclaredMethods();

    for(var i = 0; i < methods.length; i++)
    {
        methodSignature = methods[i].toGenericString();
        
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

        methodFullNameTmp = methodSignature.slice(0, initParenthesis).split(' ');
        methodFullName = methodFullNameTmp[methodFullNameTmp.length - 1];
        
        methodShortNameTmp = methodFullName.split('.')
        methodShortName = methodShortNameTmp[methodShortNameTmp.length - 1];
        
        j = initParenthesis;
        while(methodSignature[j] != ' ' && j >= 0)
        {
            j--;
        }

        newMethodSignature = methodSignature.slice(0, j) + ' ' + methodShortName;

        arguments = methodSignature.slice(initParenthesis + 1, endParenthesis).split(',');
        
        newMethodSignature += '(';

        for(var j = 0; j < arguments.length; j++)
        {
            newArgumentNameList = arguments[j].split('.');
            newArgumentName = newArgumentNameList[newArgumentNameList.length - 1];

            newMethodSignature += newArgumentName;
            if(j != arguments.length-1){
                newMethodSignature += ', ';
            }
        }

        newMethodSignature += ')';

        send(newMethodSignature);
    }
});


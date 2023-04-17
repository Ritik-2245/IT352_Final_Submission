import re

class CookieAnalyzer:
    
    def checkIntegrity(self, cookie,data={}):
       
        if data is None:
            data={}
        third_party_cookie = {}
        for key,val in cookie.items():
            if key in data.keys():
                if data[key]!=val:
                    return True
            else:
                third_party_cookie[key]=val
        
        if len(third_party_cookie.keys())>0:
            if self.CheckCookie(third_party_cookie):
                return True
        
        return False
    
    
    def detect_xss(self,cookies):
        for payload in cookies:
            
            
            # This regular expression searches for any text enclosed within <script> and </script> tags. The .*? matches any character zero or more times, but as few times as possible (non-greedy). The re.IGNORECASE flag makes the search case-insensitive, and re.DOTALL allows the . character to match any character, including newline.
            if re.search(r'<script.*?>.*?</script>', payload, re.IGNORECASE | re.DOTALL):
                return True
            

           
            # : This regular expression searches for any attribute that starts with on followed by one or more word characters (\w+?), optionally followed by whitespace (\s*=), and then a value enclosed in single or double quotes. The (.*?) captures the attribute value, allowing any characters (including newline) between the quotes, while the (\'|") and \\1 ensure that the opening and closing quotes match.
            if re.search(r'on\w+?\s*?=.*?(\'|")(.*?)\\1', payload, re.IGNORECASE | re.DOTALL):
                return True
            

           
            # This regular expression searches for any HTML element with a src attribute and captures its value. The .? matches any character (non-greedy) until it finds src attribute. \s*= optionally matches any whitespace characters before = sign and (\''|") captures the opening quote character. (.*?) captures the source URL value and (\\1) ensures that the closing quote matches the opening quote.
            if re.search(r'<.*?src\s*=\s*(\'|")(.*?)\\1', payload, re.IGNORECASE | re.DOTALL):
                return True
            
            
            # This regular expression is similar to the previous one, but instead, it searches for any HTML element with an href attribute and captures its value. .? matches any character (non-greedy) until it finds href attribute. \s*= optionally matches any whitespace characters before = sign and (\''|") captures the opening quote character. (.*?) captures the URL value, and (\\1) ensures that the closing quote matches the opening quote.
            if re.search(r'<.*?href\s*=\s*(\'|")(.*?)\\1', payload, re.IGNORECASE | re.DOTALL):
                return True
            

            
            # This regular expression searches for any HTML element that matches any of the tags listed inside the parentheses. \b ensures a word boundary before the tag name, and .*? matches any character (non-greedy) until it finds the closing angle bracket. This is used to check for any potentially dangerous elements that could be used for cross-site scripting (XSS) attacks. re.IGNORECASE makes the search case-insensitive, and re.DOTALL allows . character to match any character, including newline.
            if re.search(r'<.*?(style|script|iframe|embed|object|applet|meta|base|form|input|textarea|button|select|option|fieldset|legend|label|a|img|video|audio|source|track|canvas|svg|math|table|caption|th|tr|td|thead|tbody|tfoot|colgroup|col|pre|code|samp|kbd|var|dfn|cite|abbr|acronym|q|sub|sup|tt|i|b|big|small|em|strong|u|s|strike|center|hr|ruby|rt|rp|bdi|bdo|wbr)\b.*?>', payload, re.IGNORECASE | re.DOTALL):
                return True
           
        return False
    
    def sql_injection(self,cookies):

        patterns = [
            # This regex matches common SQL injection attack patterns, such as single quotes (') and double dashes (--). It also matches the beginning and end of multi-line comments (/* and */) as well as common SQL keywords like select, union, insert, update, delete, drop, and alter.
            r"(?:')|(?:--)|(/\\\*)|(\\\*/)|(\b(select|union|insert|update|delete|drop|alter)\b)",


            # This regex matches common URL-encoded characters used in SQL injection attacks, such as %3D (equals sign), %27 (single quote), %23 (hash), and %3B (semicolon).
            r"((?:%3D)|(?:%27)|(?:%23)|(#x3D)|(?:%3B))",
            
            # This regex matches HTML entities, which can be used in SQL injection attacks to bypass input validation filters.
            r"((?:(?:&#\d+;)?&\w+;)+)",
            

            # This regex matches common SQL injection attack patterns, such as single quotes (') and double dashes (--). It also matches the beginning and end of multi-line comments (/* and */) as well as common SQL keywords like select, union, insert, update, delete, drop, and alter.
            r"\b(select|update|insert|delete|drop|alter)\b.+?\b(select|update|insert|delete|drop|alter)\b",
             

            # This regex matches the sleep function, which can be used in SQL injection attacks to cause delays.
            r"((\d|\b)sleep\b(\d|\b))",

            # This regex matches SQL injection attacks that use the and or or operators to add additional conditions to a query. The condition is usually in the form of a comparison of two numbers.
            r"((\b(and|or)\b.+?\d+\s*=\s*\d+))",
            

            # This regex matches SQL injection attacks that use the and or or operators to add additional conditions to a query. The condition is usually in the form of a comparison of a variable to a boolean value.
            r"((\b(and|or)\b.+?\b(true|false)\b))",
            

            # This regex matches SQL injection attacks that use the union operator to combine the results of two or more queries
            r"((\bunion\b.+?\b(select|update|insert|delete|drop|alter)\b))",
            

            # This regex matches SQL injection attacks that use the from or into clauses to execute HTTP requests.
            r"((\b(select|update|insert|delete|drop|alter)\b.+?\b(from|into)\b.+?\bhttp))",
        
        ]
   
        for pattern in patterns:
            for cookie in cookies:
                if re.search(pattern, str(cookie), re.IGNORECASE):
                    return True
        return False
    
    def detect_cmd_injection(self,cookies):


   
        # This regex matches any command that is not in the list of allowed commands. The first part of the regex matches any command that is not in the list of allowed commands. The second part of the regex matches any command that starts with a pipe (|), less than (<), greater than (>), ampersand (&), single quote ('), double quote ("), dollar sign ($), or backtick (`). The third part of the regex matches any command that contains a pipe (|), less than (<), greater than (>), ampersand (&), single quote ('), double quote ("), dollar sign ($), or backtick (`). The fourth part of the regex matches any command that contains the include or require_once functions. The fifth part of the regex matches any command that contains the eval, assert, system, shell_exec, exec, passthru, popen, or proc_open functions.
        cmd_pattern =r"^(?:(?!(?i)(?<!\\)\\b(rm|mv|cp|mkdir|touch|chmod|chown|chgrp|ps|kill|shutdown|reboot|poweroff|halt|init|service|systemctl|lsb_release|uname|id|whoami|pwd|cd|echo|printf|date|cal|cat|more|less|head|tail|grep|find|awk|sed|cut|sort|uniq|wc|du|df|free|top|vmstat|sar|netstat|nc|telnet|ssh|scp|sftp|ftp|curl|wget|lynx|links|ping|traceroute|nslookup|dig)\\b).)$|(^[|<>&'\"$()].)|(.?[|<>&'\"$()].)|(.?\\b(include|require(_once)?)(\s\(.?\))?.)|(.?(?i)\\b(eval|assert|system|shell_exec|exec|passthru|popen|proc_open)\\s\(\s*(?i)(base64_decode|gzinflate|str_rot13|strtr|base_convert|convert_uudecode|urldecode|rawurldecode|hex2bin|bin2hex|gzuncompress)\s*\(\s*(.)\s\)\s*\).*)$"

        for cookie in cookies:
            if re.search(cmd_pattern, str(cookie), re.IGNORECASE):
                return True
       
        return False
        
    def CheckCookie(self, cookies):
        cookie=[]
        for _,val in cookies.items():
            cookie.append(val)
          
         
    
        if self.detect_xss(cookie):
            return True
        
        if self.detect_cmd_injection(cookie):
            return True
        
        if self.sql_injection(cookie):
            return True
    
        return False
        
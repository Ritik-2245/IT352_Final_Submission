from DeepClassifier import DeepClassifier
from CookieAnalyzer import CookieAnalyzer

class Classifier:
    def __init__(self):
        self.__deep=DeepClassifier()
        self.__cookieAnalyser=CookieAnalyzer()
        
    def predict(self,request,data=None)->bool:
        print(request.cookies)
        print(data)
        if self.__deep.predict(request):
            return True
        if len(request.cookies)==0:
            return False
        if request.cookies:
            if self.__cookieAnalyser.checkIntegrity(request.cookies,data):
                return True
            if self.__cookieAnalyser.CheckCookie(request.cookies):
                return True
        return False
        
        
from pickle import load
from tensorflow.keras.models import load_model
from urllib.parse import unquote
from tensorflow.keras.layers import Dropout
from urllib.parse import urlparse,parse_qs
def url_parse(url):
    parsed=urlparse(url)
    r=parse_qs(parsed.query)
    quer=""
    for key,val in r.items():
      quer+=" "+val[0]
    return parsed.path,quer

class DeepClassifier:
    def __init__(self):
        # loading models and tokenizer
        self.model = load_model('./files/model.h5',compile=False)
        for layer in self.model.layers:
            if isinstance(layer, Dropout):
                layer.rate = 0
        with open('./files/tokenizer.pkl', 'rb') as f:
            self.tokenizer = load(f)
        with open('./files/padded_sequence.pkl', 'rb') as f:
            self.padded_sequence = load(f)
        return

    def tokenize(self, request,path=""):
        
        pa,query=url_parse(request.url)
        text=""
        text+="uri : "+pa
        text +="\nquery : "+request.query_string.decode('utf-8')
        text +="\nmethod : "+ request.method
        
        if 'Accept' in request.headers:
            text += "\nAccept : "+request.headers['Accept']
      
        if 'Accept-Encoding' in request.headers:
            text += "\nAccept-Encoding : "+request.headers['Accept-Encoding']
     
        if 'Accept-Language' in request.headers:
            text += "\nAccept-Language : "+request.headers['Accept-Language']
       
        if 'User-Agent' in request.headers:
            text += "\nUser-Agent : "+request.headers['User-Agent']
        
        
        text=text.lower()
       
        return self.padded_sequence(self.tokenizer.texts_to_sequences([text]),maxlen=1245)
        
    def predict(self, request,path=""):
        ans=self.model.predict(self.tokenize(request,path))
       
        return ans[0][0]>0.5


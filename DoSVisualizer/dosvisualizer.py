import os
import re
import requests
import pandas as pd
from subprocess import call
from werkzeug.utils import secure_filename
from flask import Flask, request, render_template, url_for, redirect, flash
from wtforms import validators
from flask_wtf.csrf import CSRFProtect, CSRFError 

# instantiating an object of the Flask class
app = Flask(__name__, template_folder="templates", static_folder='static')

app.config['TEMPLATES_AUTO_RELOAD'] = True 

app.secret_key = 'q/w3!4er5t6y78y9=cd?u' #assign a secret key used for csrf_token
csrf = CSRFProtect(app) #Enable CSRF protection globally for a Flask app.

#Lax prevents sending cookies with CSRF-prone requests from external sites, such as submitting a form. 
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

#Custom Error message for 400 Bad Request
@app.errorhandler(400)
def error404(error):
    return '<h2>Bad Request!</h2>', 400

#Custom Error message for 404 Not Found
@app.errorhandler(404)
def error404(error):
    return '<h2>Page Not Found</h2>', 404

# Custom Error message for 500 Internal Server Errror 
@app.errorhandler(500)
def error500(error):
    return '<h2>Something Went Wrong!!!</h2>', 500
    
# Custom Error message for 405 Method Not Allowed 
@app.errorhandler(405)
def error405(error):
    return '<h2>Method is not allowed!!!</h2>', 405

#route() decorator tell Flask that when user type "/" in the address bar just after the "localhost:5000" it will 
#trigger the URL for "home" page. It binds the home() function to the URL "localhost:5000/"
@app.route('/')
 #home() is the function name which is also used to generate URL for that particular function, and returns
 # the data we want to display in the user’s browser. 
def home(): 
    return render_template("home.html") #render home.html template

@app.route('/fortesting')
def test(): 
    return render_template("test.html") #render home.html template

#secure configuration
@app.after_request
def apply_caching(response):
    #set X-Frame-Options Header "SAMEORIGIN", so page can only be displayed in a frame on the same origin 
    #as the page itself to protect against 'ClickJacking' attacks.
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    #Set headers 'X-Content-Type-Options' to 'nosniff' to force the browser to honor the response content type instead 
    #of trying to detect it, which can be abused to generate a cross-site scripting (XSS) attack.
    response.headers['X-Content-Type-Options'] = 'nosniff'
    #The browser will try to prevent reflected XSS attacks by not loading the page if the request contains something 
    #that looks like JavaScript and the response contains the same data.
    response.headers['X-XSS-Protection'] = '1; mode=block'    
    return response

#create the route and function for "capture"
@app.route('/capture')
def capture():
    return render_template("capture.html")

#after user click on "Submit and Capture" button on the "Capture Live Network Traffic" form, this function will be triggered 
@app.route('/getinput', methods=['GET', 'POST'])
def getinput():
    if request.method == "POST":
        #when user selects the option "Number of packets"
        if request.values['useroption'] == 'packets':
            #tshark command will be used for capturing a number of packets
            tsharkcmd = "tshark -i WiFi -w userinputpackets.pcap -c {}"
            userinput_filename = "userinputpackets.pcap"
        #when user selects the option "Duration"
        if request.values['useroption'] == 'duration':
            #tshark command will be used for capturing in a set time
            tsharkcmd = "tshark -i WiFi -w userinputseconds.pcap -a duration:{}"
            userinput_filename = "userinputseconds.pcap"
        userinput = request.values['userinput']
        #filter the user's input to accept digits only 
        if not(re.findall("\d+[a-zA-Z]+",userinput) or re.findall("[a-zA-Z]+\d+", userinput)):
            #pass the userinput to tshark command and then execute the tshark command in the windows terminal
            os.system(tsharkcmd.format(userinput))
        else:
            return redirect("/capture", code=302)
        #after the capturing finished, the network traffic data was saved in the file named userinput_filename as a pcap file
        #the following codes will read the pcap file with the tshark command and save the output as a csv file         
        tsharkCall = ["tshark", "-r", f"{userinput_filename}", "-T", "fields", "-e", "frame.number", "-e", "_ws.col.Time", "-e", \
        "_ws.col.Source", "-e", "_ws.col.Destination", "-e", "_ws.col.Protocol", "-e", "_ws.col.Length", "-e", "_ws.col.Info", "-E", \
        "separator=,", "-E", "quote=d", "-E", "occurrence=f"]
        with open("data.csv", "w") as tsharkOut:
            tsharkOut.write("\"Fnum\",\"Time\",\"Source\",\"Destination\",\"Protocol\",\"Length\",\"Info\"\n")
            tsharkOut.flush() #method cleans out the internal buffer.
            call(tsharkCall, stdout=tsharkOut) #take the tsharkCall as input and write output to the tsharkOut
            tsharkOut.close()
    #redirect the user to visualization page after data ready for visualizing
    return redirect("/visualization", code=302) 

#create URL and function for upload
@app.route('/upload')
def upload():
    return render_template("upload.html")
    
@app.route('/getupload', methods=['GET', 'POST'])
def getupload():
    if request.method == "POST":
        #get the uploaded file from the HTML form in the upload.html template
        f = request.files['file']
        # secure_filename(f.filename) function will change the malicious file name as meaningless name 
        f.save(secure_filename(f.filename))
        final_name = f.filename #assign the safe name
        tsharkCall = ["tshark", "-r", f"{final_name}", "-T", "fields", "-e", "frame.number", "-e", "_ws.col.Time", "-e", \
            "_ws.col.Source", "-e", "_ws.col.Destination", "-e", "_ws.col.Protocol", "-e", "_ws.col.Length", "-e", "_ws.col.Info",\
             "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]
        with open("data.csv", "w") as tsharkOut:
            tsharkOut.write("\"Fnum\",\"Time\",\"Source\",\"Destination\",\"Protocol\",\"Length\",\"Info\"\n")
            tsharkOut.flush()
            call(tsharkCall, stdout=tsharkOut)
            tsharkOut.close()
        #redirect the user to visualization page after data ready for visualizing
        return redirect("/visualization", code=302)

@app.route('/dosvisualization')
def dosvisualization(): 
    return render_template("dosvisualization.html") #render dosvisualization.html template

#create URL and function for filter
@app.route('/filter')
def filter():
    #read the data in data.csv file and store them in the dataframe object
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6]) 
    noofrows = len(dataframe.Fnum) #count number of rows in dataframe object
    return render_template("filter.html", title="Filter", dataframe=dataframe, noofrows=noofrows)

#create URL and function for visualization       
@app.route('/visualization')
def visualization():    
    return render_template("visualization.html", title="Chart")

#create URL and function for protocols       
@app.route('/protocols') # route('/protocols') decorator is to tell Flask the "/protocols" URL should trigger protocol() function
def protocols():
    #read the data in data.csv file and store them in the dataframe object
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #calculate the frequency of each protocol in dataframe   
    profreq = dataframe.Protocol.value_counts()
    numofpro = len(profreq)

    sumlength_of_eachpro = []
    for row in range(numofpro):    
        sumlength_of_eachpro.append(dataframe[dataframe.Protocol == profreq.index[row]].Length.sum()*8)
       
    #render the template protocols.html and pass the data stored in the objects profreq and numofpro
    return render_template("protocols.html", title="Chart", profreq=profreq, numofpro=numofpro, df=dataframe, \
        sumlength_of_eachpro=sumlength_of_eachpro)

'''DDOS EXTRACTION AND ANALYZATION'''
#create URL and function for DoS attacks overview       
@app.route('/dosattackoverview', methods=['GET', 'POST']) 
def dosattackoverview():
    #read the data in data.csv file and store them in the dataframe object
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #calculate the frequency of each protocol in dataframe   
    profreq = dataframe.Protocol.value_counts()
    numofpro = len(profreq)

    #Extract only HTTP protocol from dataframe object    
    http = dataframe[dataframe.Protocol == "HTTP"]
    httpfreq = len(http)

    #Calculate a number of labels and set canvas width
    if (httpfreq < 29):
        canvas_width_httpReq = 1110
    elif (httpfreq*38 < 32768):
        canvas_width_httpReq = httpfreq*38
    else:
        canvas_width_httpReq = 32768   

    #Create a dataframe that contains HTTP GET/POST requests
    httpReq = dataframe.loc[[0]].drop([0])
    for i in range(len(http)):
        httpreq = re.search("POST / HTTP/|GET / HTTP/", http.Info[http.index[i]])
        if httpreq:        
            httpReq = httpReq.append(http.loc[[http.index[i]]])    
    numOfHTTPReqs = len(httpReq)

    #Create a list of number of HTTP requests at specific times
    numofHTTPReqs_List = []
    for req in range(len(httpReq)):
        numofHTTPReqs = req + 1
        numofHTTPReqs_List.append(numofHTTPReqs)    

    #Create a list of HTTP requests per second 
    httpreqpersecond_list = []
    for req in range(len(httpReq)):
        httpreqpersecond_list.append(int(numofHTTPReqs_List[req]/httpReq.Time[httpReq.index[req]]))

    #Determine canvas width    
    numoflabels = len(dataframe.index)
    if (numoflabels < 29):
        canvas_width = 1110
    elif (numoflabels*38 < 32768):
        canvas_width = numoflabels*38
    else:
        canvas_width = 32768        

    sum_length_inMb = 0
    throughput_list = [(dataframe.Length[0]*8)/1000000]
    for index in range(len(dataframe.Length)-1):
        sum_length_inMb = sum_length_inMb + ((dataframe.Length[index])*8)/1000000
        throughput_list.append((sum_length_inMb/dataframe.Time[index+1]).round(6))

    packetsps_list = [dataframe.Fnum[0]]
    for i in range(len(dataframe.index)-1):
        packetsps = int(dataframe.Fnum[i]/dataframe.Time[i+1])
        packetsps_list.append(packetsps)           

    sumlength_of_eachpro = []
    for row in range(numofpro):    
        sumlength_of_eachpro.append(dataframe[dataframe.Protocol == profreq.index[row]].Length.sum()*8)

    Source_Info = dataframe[["Source","Info"]] #pull out the Source and Info fields in the dataframe object
    #The list of flags could be used in network traffic. The special characters [ and ] would be displayed as normal characters, so the 
    #\[ and \] are used to escape special characters [ ] to avoid the findall() method would return anything insides these [] as a list    
    flagList = ["\[SYN\]","\[SYN, ACK\]","\[ACK\]","\[PSH\]","\[PSH, ACK\]","\[FIN\]","\[FIN, ACK\]","\[RST\]","\[URG\]","\[ECE\]",\
                "\[CWR\]","\[NS\]"]
    SourceCorrespondingToFlag = [] # array/list to hold the Source IP addresses which related to flags  
    FlagInInfo = [] # list to store flags that extracted from the Info field 
    for flag in flagList: #Loop through each flag in the flagList 
        for row in range(len(Source_Info)): #each flag will be search through all rows in the Info column   
            if (re.findall(flag, str(Source_Info.Info[row]))): #if a flag found in a specific row
                x = re.findall(flag, str(Source_Info.Info[row])) #then take this flag, x is a list stores the found flag
                #append the Source IP address that corresponding to found flag
                SourceCorrespondingToFlag.append(Source_Info.Source[row])
                FlagInInfo.append(x[0]) #append the found flag to the FlagInInfo list
    # create a DataFrame for Source and Flag
    SourcenFlagDF = pd.DataFrame({'Source':SourceCorrespondingToFlag, 'Flag':FlagInInfo})
    #group the Source and Flag, Source will be set as the row label and Flag as column label
    groupbyFlagInInfo = SourcenFlagDF.groupby(['Source','Flag'])['Source'].count().unstack().fillna(0)
    numofrows = len(groupbyFlagInInfo)
    numofcolumns = len(groupbyFlagInInfo.columns)

    #render the template httpflood.html and pass the data stored in the objects profreq and numofpro
    return render_template("dosattackoverview.html", title="Chart", profreq=profreq, numofpro=numofpro, numoflabels=numoflabels,\
        sumlength_of_eachpro=sumlength_of_eachpro, throughput_list=throughput_list, canvas_width=canvas_width, df=dataframe, \
        packetsps_list=packetsps_list, groupbyFlagInInfo=groupbyFlagInInfo, numofrows=numofrows, numofcolumns=numofcolumns,\
        httpfreq=httpfreq, httpReq=httpReq, numOfHTTPReqs=numOfHTTPReqs, httpreqpersecond_list=httpreqpersecond_list, \
        canvas_width_httpReq=canvas_width_httpReq)


#create URL and function for httpflood
#route('/httpflood') decorator is to tell Flask the "/httpflood" URL should trigger httpflood() function
@app.route('/httpflood', methods=['GET','POST'])
def httpflood():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only HTTP protocol from dataframe object    
    http = dataframe[dataframe.Protocol == "HTTP"]
    httpfreq = len(http)

    #Calculate a number of labels and set canvas width
    if (httpfreq < 29):
        canvas_width_httpReq = 1110
    elif (httpfreq*38 < 32768):
        canvas_width_httpReq = httpfreq*38
    else:
        canvas_width_httpReq = 32768   

    #Create a dataframe that contains HTTP GET/POST requests
    httpReq = dataframe.loc[[0]].drop([0])
    for i in range(len(http)):
        httpreq = re.search("POST / HTTP/|GET / HTTP/", http.Info[http.index[i]])
        if httpreq:        
            httpReq = httpReq.append(http.loc[[http.index[i]]])    
    numOfHTTPReqs = len(httpReq)

    #Create a list of number of HTTP requests at specific times
    numofHTTPReqs_List = []
    for req in range(len(httpReq)):
        numofHTTPReqs = req + 1
        numofHTTPReqs_List.append(numofHTTPReqs)    

    #Create a list of HTTP requests per second 
    httpreqpersecond_list = []
    for req in range(len(httpReq)):
        httpreqpersecond_list.append(int(numofHTTPReqs_List[req]/httpReq.Time[httpReq.index[req]]))

    #Generate a dataframe which consists of only HTTP Responds
    httpRes = dataframe.loc[[0]].drop([0])
    for i in range(httpfreq):
        respond = re.search("HTTP/.+200 OK", http.Info[http.index[i]])
        if respond:
            httpRes = httpRes.append(http.loc[[http.index[i]]])
    numofHTTPRes = len(httpRes)

    #Calculate frequency of each protocol
    profreq = dataframe.Protocol.value_counts()
    numofpro = len(profreq)

    #Calculate a number of labels and set canvas width
    numoflabels = len(dataframe.index)
    
    #Set requests per second threshold
    rps_threshold = 350 # Set default threshold
    # Get user's threshold
    if request.method == "POST":
        userinput = request.values['rpsthreshold']
        #filter the user's input to accept digits only 
        if not(re.findall("\d*[a-zA-Z]+\d*", userinput)):
            rps_threshold = int(userinput)
        else:
            return redirect("/httpflood", code=302)            

    #render the template httpflood.html and pass the data stored in the objects 
    return render_template("httpflood.html", title="HTTPFlood", profreq=profreq, numofpro=numofpro, df=dataframe, http=http,\
        rps_threshold=rps_threshold, numoflabels=numoflabels, httpfreq=httpfreq, httpReq=httpReq,httpRes=httpRes, \
        numOfHTTPReqs=numOfHTTPReqs, httpreqpersecond_list=httpreqpersecond_list, numofHTTPRes=numofHTTPRes,\
        canvas_width_httpReq=canvas_width_httpReq)      


#create URL and function for tcpflood
@app.route('/tcpflood', methods=['GET', 'POST'])# decorator is to tell Flask the "/tcpflood" URL should trigger tcpflood() function
def tcpflood():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only HTTP protocol from dataframe object    
    tcp = dataframe[dataframe.Protocol == "TCP"]
    tcpfreq = len(tcp)

    #Calculate frequency of each protocol
    profreq = dataframe.Protocol.value_counts()
    numofpro = len(profreq)

    #Calculate a number of labels and set canvas width
    numoflabels = len(dataframe.index)
    if (numoflabels < 29):
        canvas_width = 1110
    elif (numoflabels*38 < 32768):
        canvas_width = numoflabels*38
    else:
        canvas_width = 32768 

    #Set packets per second threshold
    tcpSYNpps_threshold = 100 # Set default threshold
    # Get user's threshold
    if request.method == "POST":
        userinput = request.values['ppsthreshold']
        #filter the user's input to accept digits only 
        if not(re.findall("\d*[a-zA-Z]+\d*", userinput)):
            tcpSYNpps_threshold = int(userinput)
        else:
            return redirect("/tcpflood", code=302)               

    #Create a list for sum of length of each protocol
    sumlength_of_eachpro = []
    for row in range(numofpro):    
        sumlength_of_eachpro.append(dataframe[dataframe.Protocol == profreq.index[row]].Length.sum()*8)

    Source_Info = dataframe[["Source","Info"]] #pull out the Source and Info fields in the dataframe object
    #The list of flags could be used in network traffic. The special characters [ and ] would be displayed as normal characters, so the 
    #\[ and \] are used to escape special characters [ ] to avoid the findall() method would return anything insides these [] as a list    
    flagList = ["\[SYN\]","\[SYN, ACK\]","\[ACK\]","\[PSH\]","\[PSH, ACK\]","\[FIN\]","\[FIN, ACK\]","\[RST\]","\[URG\]","\[ECE\]",\
                "\[CWR\]","\[NS\]"]
    SourceCorrespondingToFlag = [] # array/list to hold the Source IP addresses which related to flags  
    FlagInInfo = [] # list to store flags that extracted from the Info field 
    for flag in flagList: #Loop through each flag in the flagList 
        for row in range(len(Source_Info)): #each flag will be search through all rows in the Info column   
            if (re.findall(flag, str(Source_Info.Info[row]))): #if a flag found in a specific row
                x = re.findall(flag, str(Source_Info.Info[row])) #then take this flag, x is a list stores the found flag
                #append the Source IP address that corresponding to found flag
                SourceCorrespondingToFlag.append(Source_Info.Source[row])
                FlagInInfo.append(x[0]) #append the found flag to the FlagInInfo list
    # create a DataFrame for Source and Flag
    Source_Flag_DF = pd.DataFrame({'Source':SourceCorrespondingToFlag, 'Flag':FlagInInfo})
    #group the Source and Flag, Source will be set as the row label and Flag as column label
    groupbyFlagInInfo = Source_Flag_DF.groupby(['Source','Flag'])['Source'].count().unstack().fillna(0)
    numofrows = len(groupbyFlagInInfo)
    numofcolumns = len(groupbyFlagInInfo.columns)

    #Group all flags in groups
    groupofflags = Source_Flag_DF.Flag.value_counts()
    numofgroupsofflags = len(groupofflags)

    #Create a dataframe that contains only TCP SYN flags
    tcpSYNflags_df = tcp.loc[[tcp.index[0]]].drop([0])
    for i in range(len(tcp)):
        tcpflag = re.search("\[SYN\]|\[SYN, ACK\]|\[ACK\]|\[PSH\]|\[PSH, ACK\]|\[FIN\]|\[FIN, ACK\]|\[RST\]|\[URG\]|\[ECE\]|\[CWR\]|\[NS\]",\
                 tcp.Info[tcp.index[i]])
        if tcpflag.group() == "[SYN]":        
            tcpSYNflags_df = tcpSYNflags_df.append(tcp.loc[[tcp.index[i]]])

    #Generate a list of TCP SYN packets per second
    numOfSYN_packets = 1
    tcpSYN_pps = [1]
    for i in range(len(tcpSYNflags_df)-1):
        numOfSYN_packets = numOfSYN_packets + 1
        tcpSYN_pps.append(int(numOfSYN_packets/tcpSYNflags_df.Time[tcpSYNflags_df.index[i+1]]))

    #render the template tcpflood.html and pass the data stored in the objects 
    return render_template("tcpflood.html", titltcpSYNflags_dfe="TCP Flood", profreq=profreq, numofpro=numofpro, df=dataframe, tcpfreq=tcpfreq,\
        numoflabels=numoflabels, sumlength_of_eachpro=sumlength_of_eachpro, canvas_width=canvas_width,groupbyFlagInInfo=groupbyFlagInInfo,\
        numofrows=numofrows, numofcolumns=numofcolumns, groupofflags=groupofflags, numofgroupsofflags=numofgroupsofflags, tcp=tcp,\
        tcpSYNpps_threshold=tcpSYNpps_threshold, tcpSYN_pps=tcpSYN_pps, tcpSYNflags_df=tcpSYNflags_df) 


#create URL and function for UDP flood 
# route('/udpflood') decorator is to tell Flask the "/udpflood" URL should trigger udpflood() function
@app.route('/udpflood', methods=["GET", "POST"])
def udpflood():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Calculate frequency of each protocol
    profreq = dataframe.Protocol.value_counts()
    numofpro = len(profreq)

    numoflabels = len(dataframe.index)
    #Decide canvas width
    if (numoflabels < 29):
        canvas_width = 1110
    elif (numoflabels*38 < 32768):
        canvas_width = numoflabels*38
    else:
        canvas_width = 32768

    #Generate a throughput list (in Mbps)    
    sum_length_inMb = 0
    throughput_list = [(dataframe.Length[0]*8)/1000000]
    for index in range(len(dataframe.Length)-1):
        sum_length_inMb = sum_length_inMb + ((dataframe.Length[index])*8)/1000000
        throughput_list.append((sum_length_inMb/dataframe.Time[index+1]).round(6))
    numofelements = len(throughput_list)

    #Create a list for sum of length of each protocol
    sumlength_of_eachpro = []
    for row in range(numofpro):    
        sumlength_of_eachpro.append(dataframe[dataframe.Protocol == profreq.index[row]].Length.sum()*8)  

    #Set bandwidth threshold
    mbps_threshold = 30 # Set default threshold
    # Get user's threshold
    if request.method == "POST":
        userinput = request.values['mbpsthreshold']
        #filter the user's input to accept digits only 
        if not(re.findall("\d*[a-zA-Z]+\d*", userinput)):
            mbps_threshold = float(userinput)
        else:
            return redirect("/udpflood", code=302)      

    return render_template("udpflood.html", title="UDP Flood", numofpro=numofpro, profreq=profreq, df=dataframe, \
        sumlength_of_eachpro=sumlength_of_eachpro, throughput_list=throughput_list, canvas_width=canvas_width, \
        mbps_threshold=mbps_threshold, numofelements=numofelements)


#create URL and function for icmpflood
@app.route('/icmpflood', methods=["GET", "POST"])
def icmpflood():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Calculate frequency of each protocol
    profreq = dataframe.Protocol.value_counts()
    numofpro = len(profreq)
    numoflabels = len(dataframe.index)

    # Determine canvas width
    if (numoflabels < 29):
        canvas_width = 1110
    elif (numoflabels*38 < 32768):
        canvas_width = numoflabels*38
    else:
        canvas_width = 32768

    #Create a list for sum of length of each protocol
    sumlength_of_eachpro = []
    for row in range(numofpro):    
        sumlength_of_eachpro.append(dataframe[dataframe.Protocol == profreq.index[row]].Length.sum()*8)

    #Generate a throughput list (in Mbps)    
    sum_length_inMb = 0
    throughput_list = [(dataframe.Length[0]*8)/1000000]
    for index in range(len(dataframe.Length)-1):
        sum_length_inMb = sum_length_inMb + ((dataframe.Length[index])*8)/1000000
        throughput_list.append((sum_length_inMb/dataframe.Time[index+1]).round(6))
    numofelements = len(throughput_list)

    #Set throughput threshold
    mbps_threshold = 30 # Set default threshold
    # Get user's threshold
    if request.method == "POST":
        userinput = request.values['mbpsthreshold']
        #filter the user's input to accept digits only 
        if not(re.findall("\d*[a-zA-Z]+\d*", userinput)):
            mbps_threshold = float(userinput)
        else:
            return redirect("/icmpflood", code=302)              

    return render_template("icmpflood.html", title="ICMP Ping Flood", icmp=icmp, profreq=profreq, numofpro=numofpro, df=dataframe,\
    sumlength_of_eachpro=sumlength_of_eachpro, canvas_width=canvas_width, throughput_list=throughput_list, mbps_threshold=mbps_threshold,\
    numofelements=numofelements) 


#create URL and function for icmpflood
@app.route('/ipfragmentation', methods=["GET", "POST"])
def ipfragmentation():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Calculate frequency of each protocol
    profreq = dataframe.Protocol.value_counts()
    numofpro = len(profreq)
    numoflabels = len(dataframe.index)

    # Determine canvas width
    if (numoflabels < 29):
        canvas_width = 1110
    elif (numoflabels*38 < 32768):
        canvas_width = numoflabels*38
    else:
        canvas_width = 32768

    #Create a list for sum of length of each protocol
    sumlength_of_eachpro = []
    for row in range(numofpro):    
        sumlength_of_eachpro.append(dataframe[dataframe.Protocol == profreq.index[row]].Length.sum()*8)

    #Generate a Packets per second (Pps) list
    packetsps_list = [dataframe.Fnum[0]]
    for i in range(len(dataframe.index)-1):
        packetsps = int(dataframe.Fnum[i]/dataframe.Time[i+1])
        packetsps_list.append(packetsps)             
    numofelements = len(packetsps_list)

    #Set packets per second threshold
    pps_threshold = 100000 # Set default threshold
    # Get user's threshold
    if request.method == "POST":
        userinput = request.values['ppsthreshold']
        #filter the user's input to accept digits only 
        if not(re.findall("\d*[a-zA-Z]+\d*", userinput)):
            pps_threshold = int(userinput)
        else:
            return redirect("/ipfragmentation", code=302) 

    return render_template("ipfragmentation.html", title="IP Fragmentation", profreq=profreq, numofpro=numofpro, df=dataframe,\
        sumlength_of_eachpro=sumlength_of_eachpro, canvas_width=canvas_width, pps_threshold=pps_threshold, numofelements=numofelements,\
        packetsps_list=packetsps_list) 
   
'''END DOS ANALYSIS'''  

#create URL and function for sourceport   
@app.route('/sourceport')
def sourceport():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    info = dataframe.Info
        
    liststoresports=[] #the list of lists to store pairs of source port and destination port
    srccorrespondingtoport=[] #an array to store the source IP address corresponding to port
    #Extract Source ports from the Info field  
    for row in range(len(info)):
        #if each word in each row of Info does not start with a digit and follow by a letter/letters
        #or does not start with a letter/letters and end with a digit
        if not(re.findall("\d+[a-zA-Z]+", str(info[row])) or re.findall("[a-zA-Z]+\d+", str(info[row])) or \
            re.findall(r"\d+[.,?/\|#<>:;'@!£$%&()-]\b",str(info[row])) or re.findall(r"[.,?/\|#<>:;'@!£$%&()-]\d+",str(info[row]))):
            rowcontainsnum=re.findall("\d+",str(info[row]))
            if not(rowcontainsnum==[]): #if each time the array rowcontainsnum starts with a number 
                srccorrespondingtoport.append(dataframe.Source[row])                
                for n in range(1):
                    #append a pair of source port and destination port into liststoresports array
                    liststoresports.append([rowcontainsnum[n],rowcontainsnum[n+1]])
    
    #Store source ports and destination ports in seperated arrays 
    srcports=[] #the array to keep source ports
    dstports=[] #the array to keep destination ports
    for row in range(len(liststoresports)):
        for col in range(2):
            if col==0:
                srcports.append(liststoresports[row][col])
            else:
                dstports.append(liststoresports[row][col])  

    # create a dataframe for Source and Port
    SrcnPortDF = pd.DataFrame({'Source':srccorrespondingtoport, 'Port':srcports})
    groupbySrcPort = SrcnPortDF.groupby(['Source','Port'])['Source'].count().unstack().fillna(0)
    numofrows = len(groupbySrcPort)
    numofcolumns = len(groupbySrcPort.columns)

    if (numofcolumns < 29):
        canvas_width = 1110
    elif (numofcolumns*38 < 32768):
        canvas_width = numofcolumns*38
    else:
        canvas_width = 32768    

    return render_template("sourceport.html", title="DstPort Chart", groupbySrcPort=groupbySrcPort, numofrows=numofrows, \
        numofcolumns=numofcolumns, canvas_width=canvas_width)    

#create URL and function for dstport       
#Extract Destination ports from the Info column 
@app.route('/dstport')
def dstport():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    info = dataframe.Info #Extract the Info field and save it to the info object    
    
    liststoresports=[] #the list of lists to store pairs of source port and destination port    
    dstcorrespondingtoport=[] #an array to store the destination IP address corresponding to port 
    for row in range(len(info)):
        #if each group of characters in each row of Info field does not start with a digit/digits and follow by a letter/letters or 
        # ".,?/\|#<>:;'@!£$%&()-" or does not start with a letter/letters or ".,?/\|#<>:;'@!£$%&()-" and end with a digit/digits
        if not(re.findall("\d+[a-zA-Z]+",str(info[row])) or re.findall("[a-zA-Z]+\d+",str(info[row])) or \
            re.findall(r"\d+[.,?/\|#<>:;'@!£$%&()-]\b",str(info[row])) or re.findall(r"[.,?/\|#<>:;'@!£$%&()-]+\d+",str(info[row]))):
            rowcontainsnum=re.findall("\d+",str(info[row])) #find all numbers in the Info field and return to rowcontainsnum list
            if not(rowcontainsnum==[]): #if each time the array rowcontainsnum contains a number                 
                dstcorrespondingtoport.append(dataframe.Destination[row])
                for n in range(1):
                    #append a pair of source port and destination port into liststoresports list
                    liststoresports.append([rowcontainsnum[n],rowcontainsnum[n+1]])
       
    #Store source ports and destination ports in seperated arrays 
    srcports=[] #the array to keep source ports
    dstports=[] #the array to keep destination ports
    for row in range(len(liststoresports)):
        for col in range(2):
            if col==0:
                srcports.append(liststoresports[row][col])
            else:
                dstports.append(liststoresports[row][col])

    # create a dataframe for Destination and Port
    DstPortDF = pd.DataFrame({'Source':dstcorrespondingtoport, 'Port':dstports})
    groupbyDstPort = DstPortDF.groupby(['Source','Port'])['Source'].count().unstack().fillna(0)
    numofrows = len(groupbyDstPort)
    numofcolumns = len(groupbyDstPort.columns)
    if (numofcolumns < 29):
        canvas_width = 1110
    elif (numofcolumns*38 < 32768):
        canvas_width = numofcolumns*38
    else:
        canvas_width = 32768    

    return render_template("dstport.html", title="Chart", groupbyDstPort=groupbyDstPort, numofrows=numofrows, \
        numofcolumns=numofcolumns, canvas_width=canvas_width)


#create URL and function for source 
@app.route('/source')
def source():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Pull out the Source IP addresses and count the frequency of each one 
    source = dataframe.Source.value_counts()
    sumsrc = len(source)

    return render_template("source.html", title="Chart", sumsrc=sumsrc, source=source)

#create URL and function for destination 
@app.route('/destination')
def destination():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Pull out the Destination IP addresses and count the frequency of each one 
    destination = dataframe.Destination.value_counts()
    dstrows = len(destination)

    return render_template("destination.html", title="Chart", dstrows=dstrows, destination=destination)

#create URL and function for groupbysource 
@app.route('/groupbysource')
def groupbysource():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #group the Source and Protocol, Protocol will be set as the row label and Source as column label    
    groupbySource = dataframe.groupby(['Source','Protocol'])['Source'].count().unstack(0).fillna(0)
    numofrows = len(groupbySource)
    numofcolumns = len(groupbySource.columns)
    if (numofcolumns < 29):
        canvas_width = 1110
    elif (numofcolumns*38 < 32768):
        canvas_width = numofcolumns*38
    else:
        canvas_width = 32768    

    return render_template("groupbysource.html", title="Chart", numofcolumns=numofcolumns, numofrows=numofrows, \
        groupbySource=groupbySource, canvas_width=canvas_width)

#create URL and function for groupbyprotocol
@app.route('/groupbyprotocol') # The decorator tells Flask "/groupbyprotocol" URL should trigger groupbyprotocol() function
def groupbyprotocol(): 
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    # Group 'Source' and 'Protocol' together, count the Source IP address for each protocol, 
    #the method unstack() is to seperate Source IP addresses as row labels and protocols as column labels
    #the fillna(0) method fills all Nan with 0
    groupbyProtocol = dataframe.groupby(['Source','Protocol'])['Source'].count().unstack().fillna(0)
    #count the number of rows in groupbyProtocol object
    numofrows = len(groupbyProtocol)
    #count the number of columns in groupbyProtocol object
    numofcolumns = len(groupbyProtocol.columns)
    if (numofcolumns < 29):
        canvas_width = 1110
    elif (numofcolumns*38 < 32768):
        canvas_width = numofcolumns*38
    else:
        canvas_width = 32768    
    #display the result on a table and a chart by rendering the groupbyprotocol.html template
    return render_template("groupbyprotocol.html", title="Chart", numofcolumns=numofcolumns, numofrows=numofrows, \
        groupbyProtocol=groupbyProtocol, canvas_width=canvas_width)

#create URL and function for tcp
@app.route('/tcp')
def tcp():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only TCP protocol from the dataframe object
    tcp = dataframe[dataframe.Protocol == "TCP"]
    tcpfreq = len(tcp)
    if (tcpfreq < 29):
        canvas_width = 1110
    elif (tcpfreq*38 < 32768):
        canvas_width = tcpfreq*38
    else:
        canvas_width = 32768    
    #plt.xticks(np.arange(51))
    return render_template("tcp.html", title="Chart", tcp=tcp, tcpfreq=tcpfreq, canvas_width=canvas_width)

#create URL and function for http
@app.route('/http')
def http():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only HTTP protocol from dataframe object    
    http = dataframe[dataframe.Protocol == "HTTP"]
    frequency= len(http)

    if (frequency < 29):
        canvas_width = 1110
    elif (frequency*38 < 32768):
        canvas_width = frequency*38
    else:
        canvas_width = 32768    

    return render_template("http.html", title="Chart", http=http, frequency=frequency, canvas_width=canvas_width)    

#create URL and function for tcp
@app.route('/udp')
def udp():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only UDP protocol from the dataframe object           
    udp = dataframe[dataframe.Protocol == "UDP"]
    udpfreq= len(udp)
    if (udpfreq < 29):
        canvas_width = 1110
    elif (udpfreq*38 < 32768):
        canvas_width = udpfreq*38
    else:
        canvas_width = 32768    

    return render_template("udp.html", title="Chart", udp=udp, udpfreq=udpfreq, canvas_width=canvas_width)

#create URL and function for dns
@app.route('/dns')
def dns():    
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only DNS protocol from dataframe object        
    dns = dataframe[dataframe.Protocol == "DNS"]
    dnsfreq= len(dns)
    if (dnsfreq < 29):
        canvas_width = 1110
    elif (dnsfreq*38 < 32768):
        canvas_width = dnsfreq*38
    else:
        canvas_width = 32768    
    return render_template("dns.html", title="Chart", dns=dns, dnsfreq=dnsfreq, canvas_width=canvas_width)

#create URL and function for tlsv1
@app.route('/tlsv1')
def tlsv1():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only TLSv1 protocol from dataframe object        
    tlsv1 = dataframe[dataframe.Protocol == "TLSv1"]
    tlsv1freq = len(tlsv1)
    if (tlsv1freq < 29):
        canvas_width = 1110
    elif (tlsv1freq*38 < 32768):
        canvas_width = tlsv1freq*38
    else:
        canvas_width = 32768    

    return render_template("tlsv1.html", title="Chart", tlsv1=tlsv1, tlsv1freq=tlsv1freq, canvas_width=canvas_width)

#create URL and function for tlsv1.2
@app.route('/tlsv1_2')
def tlsv1_2():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only TLSv1.2 protocol from dataframe object        
    tlsv1_2 = dataframe[dataframe.Protocol == "TLSv1.2"]
    tlsv1_2freq = len(tlsv1_2)
    if (tlsv1_2freq < 29):
        canvas_width = 1110
    elif (tlsv1_2freq*38 < 32768):
        canvas_width = tlsv1_2freq*38
    else:
        canvas_width = 32768    

    return render_template("tlsv1_2.html", title="Chart", tlsv1_2=tlsv1_2, tlsv1_2freq=tlsv1_2freq, canvas_width=canvas_width)

#create URL and function for tlsv1.3
@app.route('/tlsv1_3')
def tlsv1_3():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only TLSv1.3 protocol from dataframe object        
    tlsv1_3 = dataframe[dataframe.Protocol == "TLSv1.3"]
    tlsv1_3freq = len(tlsv1_3)
    if (tlsv1_3freq < 29):
        canvas_width = 1110
    elif (tlsv1_3freq*38 < 32768):
        canvas_width = tlsv1_3freq*38
    else:
        canvas_width = 32768    

    return render_template("tlsv1_3.html", title="Chart", tlsv1_3=tlsv1_3, tlsv1_3freq=tlsv1_3freq, canvas_width=canvas_width)

#create URL and function for telnet
@app.route('/telnet')
def telnet():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only TELNET protocol from dataframe object        
    telnet = dataframe[dataframe.Protocol == "TELNET"]
    telnetfreq= len(telnet)
    if (telnetfreq < 29):
        canvas_width = 1110
    elif (telnetfreq*38 < 32768):
        canvas_width = telnetfreq*38
    else:
        canvas_width = 32768    

    return render_template("telnet.html", title="Chart", telnet=telnet, telnetfreq=telnetfreq, canvas_width=canvas_width)

#create URL and function for ssdp
@app.route('/ssdp')
def ssdp():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only SSDP protocol from dataframe object        
    ssdp = dataframe[dataframe.Protocol == "SSDP"]
    ssdpfreq= len(ssdp)
    if (ssdpfreq < 29):
        canvas_width = 1110
    elif (ssdpfreq*38 < 32768):
        canvas_width = ssdpfreq*38
    else:
        canvas_width = 32768    
    return render_template("ssdp.html", title="Chart", ssdp=ssdp, ssdpfreq=ssdpfreq, canvas_width=canvas_width)

#create URL and function for arp
@app.route('/arp')
def arp():    
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only ARP protocol from dataframe object       
    arp = dataframe[dataframe.Protocol == "ARP"]
    arpfreq= len(arp)
    if (arpfreq < 29):
        canvas_width = 1110
    elif (arpfreq*38 < 32768):
        canvas_width = arpfreq*38
    else:
        canvas_width = 32768    
    return render_template("arp.html", title="Chart", arp=arp, arpfreq=arpfreq, canvas_width=canvas_width)

#create URL and function for icmp
@app.route('/icmp')
def icmp():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only ICMP protocol from dataframe object        
    icmp = dataframe[dataframe.Protocol == "ICMP"]
    frequency= len(icmp)
    if (frequency < 29):
        canvas_width = 1110
    elif (frequency*38 < 32768):
        canvas_width = frequency*38
    else:
        canvas_width = 32768    
    return render_template("icmp.html", title="Chart", icmp=icmp, frequency=frequency, canvas_width=canvas_width)        

#create URL and function for icmpv6    
@app.route('/icmpv6')
def icmpv6():    
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only ICMPv6 protocol from dataframe object        
    icmpv6 = dataframe[dataframe.Protocol == "ICMPv6"]
    frequency= len(icmpv6)
    if (frequency < 29):
        canvas_width = 1110
    elif (frequency*38 < 32768):
        canvas_width = frequency*38
    else:
        canvas_width = 32768                
    return render_template("icmpv6.html", title="Chart", icmp=icmp, frequency=frequency, canvas_width=canvas_width)    

#create URL and function for ocsp
@app.route('/ocsp')
def ocsp():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only OCSP protocol from dataframe object        
    ocsp = dataframe[dataframe.Protocol == "OCSP"]
    frequency= len(ocsp)
    if (frequency < 29):
        canvas_width = 1110
    elif (frequency*38 < 32768):
        canvas_width = frequency*38
    else:
        canvas_width = 32768    
    return render_template("ocsp.html", title="Chart", ocsp=ocsp, frequency=frequency, canvas_width=canvas_width)       

#create URL and function for dhcpv6    
@app.route('/dhcpv6')
def dhcpv6():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only DHCPv6 protocol from dataframe object        
    dhcpv6 = dataframe[dataframe.Protocol == "DHCPv6"]
    frequency= len(dhcpv6)
    if (frequency < 29):
        canvas_width = 1110
    elif (frequency*38 < 32768):
        canvas_width = frequency*38
    else:
        canvas_width = 32768                 
    return render_template("dhcpv6.html", title="Chart", dhcpv6=dhcpv6, frequency=frequency, canvas_width=canvas_width)       

#create URL and function for mdns (Multicast Domain Name System query)
@app.route('/mdns')
def mdns():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only MDNS protocol from dataframe object        
    mdns = dataframe[dataframe.Protocol == "MDNS"]
    frequency= len(mdns)
    if (frequency < 29):
        canvas_width = 1110
    elif (frequency*38 < 32768):
        canvas_width = frequency*38
    else:
        canvas_width = 32768                        
    return render_template("mdns.html", title="Chart", mdns=mdns, frequency=frequency, canvas_width=canvas_width)        
    
#create URL and function for db_lsp_disc (Dropbox LAN Sync Discovery Protocol)
@app.route('/db_lsp_disc')
def db_lsp_disc():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only DB-LSD-DISC protocol from dataframe object        
    db_lsp_disc = dataframe[dataframe.Protocol == "DB-LSP-DISC"]
    db_lsp_discfreq= len(db_lsp_disc)
    if (db_lsp_discfreq < 29):
        canvas_width = 1110
    elif (db_lsp_discfreq*38 < 32768):
        canvas_width = db_lsp_discfreq*38
    else:
        canvas_width = 32768                            
    return render_template("db_lsp_disc.html", title="Chart", db_lsp_disc=db_lsp_disc, db_lsp_discfreq=db_lsp_discfreq,\
     canvas_width=canvas_width)

#create URL and function for nbns (NetBIOS Name Service)
@app.route('/nbns')
def nbns():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only NBNS protocol from dataframe object        
    nbns = dataframe[dataframe.Protocol == "NBNS"]
    frequency= len(nbns)
    if (frequency < 29):
        canvas_width = 1110
    elif (frequency*38 < 32768):
        canvas_width = frequency*38
    else:
        canvas_width = 32768                            
    return render_template("nbns.html", title="Chart", nbns=nbns, frequency=frequency, canvas_width=canvas_width)           
    
#create URL and function for browser (Microsoft Windows Browser Protocol)
@app.route('/browser')
def browser():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only BROWSER protocol from dataframe object        
    browser = dataframe[dataframe.Protocol == "BROWSER"]
    browserfreq= len(browser)
    if (browserfreq < 29):
        canvas_width = 1110
    elif (browserfreq*38 < 32768):
        canvas_width = browserfreq*38
    else:
        canvas_width = 32768                                  
    return render_template("browser.html", title="Chart", browser=browser, browserfreq=browserfreq, canvas_width=canvas_width) 

#create URL and function for igmpv2 (Internet Group Management Protoco v2)
@app.route('/igmpv2')
def igmpv2():
    dataframe = pd.read_csv("data.csv", usecols=[0, 1, 2, 3, 4, 5, 6])
    #Extract only IGMPv2 protocol from dataframe object    
    igmpv2 = dataframe[dataframe.Protocol == "IGMPv2"]
    frequency= len(igmpv2)
    if (frequency < 29):
        canvas_width = 1110
    elif (frequency*38 < 32768):
        canvas_width = frequency*38
    else:
        canvas_width = 32768           
    return render_template("igmpv2.html", title="Chart", igmpv2=igmpv2, frequency=frequency, canvas_width=canvas_width)   
  

#Run the app if __name='__main__'
if __name__ == '__main__':
    app.run(host="localhost", port=5000, debug=False)

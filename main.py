import cv2
import asyncio
import threading
import time
import datetime
import queue
import os
from collections import deque
from fastapi.responses import FileResponse
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from ultralytics import YOLO
from huggingface_hub import hf_hub_download

app=FastAPI(title="CIPHER")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

cameraurl="http://127.0.0.1:5000/"      #url of the live stream. code from camsimulation.py
currentframebytes=None

preeventframes=int(8 * 15.0)      #seconds * target FPS
posteventframes=int(8 * 15.0)      #seconds * target FPS
framebuffer=deque(maxlen=preeventframes)
isrecording=False
posteventcounter=0
videowriter=None
activeincidentpath=None

#for incident clips storage
os.makedirs("incidents", exist_ok=True)

rawframequeue=queue.Queue(maxsize=1)

modelpath=hf_hub_download(repo_id="Subh775/Threat-Detection-YOLOv8n", filename="weights/best.pt")
model=YOLO(modelpath)    #initializing model

#Producer Thread: Pulls frames from the camera and places them onto the queue
def streamreaderthread():
    global rawframequeue
    capture=cv2.VideoCapture(cameraurl) 
    
    while True:
        if not capture.isOpened():                      #if no video feed is available
            print("The Camera is not Connected. Retrying in 1s")
            time.sleep(1)    
            capture=cv2.VideoCapture(cameraurl)  
            continue

        success,frame=capture.read()            #if camera feed is available: read the frame
        if not success:
            print("Dropped Frame. Re-establishing the stream")
            capture.release()
            time.sleep(1)
            capture=cv2.VideoCapture(cameraurl)
            continue

        
        if rawframequeue.full():        #when the new frame is grabbed, but the queue is full
            try:
                rawframequeue.get_nowait()  #delete the current frame
            except queue.Empty:
                pass

        try:
            rawframequeue.put_nowait(frame) #insert the new frame into the queue.
        except queue.Full:
            pass

#Consumer Thread: Pulls the latest frames from the Queue and runs Yolo Inference
def inferenceworkerthread():
    global currentframebytes, isrecording, posteventcounter, videowriter, activeincidentpath

    consecutivehits=0
    requiredhits=2
    
    while True:
        try:
            frame=rawframequeue.get(timeout=1.0)    #get the frame from the queue
        except queue.Empty:
            continue

        #YOLO Proccessing here
        result=model(frame, conf=0.40, imgsz=640, verbose=False)      #classes=[0] targets persons only, verbose=False suppresses thinking logs
        labelledframe=result[0].plot()

        framebuffer.append(labelledframe)           #continuosly push the frame into the frame buffer inorder to roll pre-event clips

        boxes=result[0].boxes                   #check if there is any event happening
        for box in result[0].boxes:
            classid=int(box.cls[0])
            confidence=float(box.conf[0])
            classname=model.names[classid]
            print(f"Detected: {classname} ({classid}) with {confidence:.2f} confidence")

        
        if len(boxes)>0:
            consecutivehits=consecutivehits+1
        else:
            consecutivehits=0

        #if any event is happening and if its not already recording then, save pre event clips
        if consecutivehits>=requiredhits  and not isrecording:
            print("Incident Detected- Stitching up and saving the clips")
            isrecording=True
            posteventcounter=0

            timestamp=datetime.datetime.now().strftime("%Y%m%d_%H%M%S")         #set timestamp in the video recording
            activeincidentpath=os.path.join("incidents", f"incident_{timestamp}.mp4")

            fourcc=cv2.VideoWriter_fourcc(*'mp4v')          #fourcc is an indentifier which tells the system which compression algorithm to apply
            height,width,_=labelledframe.shape              #set video height and width same as labelled video height and width
            videowriter=cv2.VideoWriter(activeincidentpath, fourcc, 15.0, (width,height))    #declaring parameters of videowriter- where to save, how to save etc

            #dump already recorded frames into filename as pre-event footage
            for bufferedframe in framebuffer:
                videowriter.write(bufferedframe)
            print("Pre Event Frames are saved!")

        #for post event clip saving
        if isrecording:
            videowriter.write(labelledframe)
            posteventcounter+=1

            if posteventcounter>=posteventframes:   #when the post event queue is full, stop the recording
                videowriter.release()
                isrecording=False
                consecutivehits=0                   #reset hit counter
                framebuffer.clear()
                print("Post Event Recording Compelete")

        #compressing video frames to JPEG Images
        _,buffer=cv2.imencode('.jpg',labelledframe)
        currentframebytes=buffer.tobytes()
        


@app.on_event("startup")
async def startupevent():
    #Start the camera recorder loop
    readerthread=threading.Thread(target=streamreaderthread, daemon=True)
    readerthread.start()

    #Start the processing thread 
    workerthread=threading.Thread(target=inferenceworkerthread, daemon=True)
    workerthread.start()
    print("Both Reader and Inference worker Thread has started!")


#this endpoint will be used by frontend to stream video
@app.websocket("/ws/video")
async def videowebsocket(websocket: WebSocket):         
    await websocket.accept()
    print("Client connected to WebSocket")

    try:
        while True:
            if currentframebytes:
                await websocket.send_bytes(currentframebytes)   #send bytes to software
                await asyncio.sleep(0.033)          #30FPS

    except WebSocketDisconnect:
        print("Client disconnected")
    except Exception as e:
        print(f"WebSocket error: {e}")

@app.get("/")
async def get_test_page():
    """Serves a basic HTML page to test the WebSocket stream."""
    return FileResponse("stream.html")

#for laptop only
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app,port=8000)

#cross platform- use ipcongif IPv4 Addess as host
'''if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app,host="0.0.0.0" ,port=8000)'''


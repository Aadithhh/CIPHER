import httpx
from fastapi import APIRouter, HTTPException, status
from auth.schemas import LoginRequest, AuthenticationResponse
from auth.firebaseconfig import webapikey, db

router=APIRouter(prefix="/auth", tags=["Authentication"])

identifytoolkitURL=(
    f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
    f"?key={webapikey}"
)

@router.post("/login", response_model=AuthenticationResponse)
async def login(credentials: LoginRequest):

    #preparing payload for authentication
    payload={
        "email":credentials.email,
        "password":credentials.password,
        "returnSecureToken":True
    }

    async with httpx.AsyncClient() as client:
        try:
            response=await client.post(identifytoolkitURL, json=payload, timeout=10.0)  #calling authentication endpoint
            data=response.json()
        except httpx.RequestError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)

        if response.status_code != 200:
            errormessage=data.get("error", {}).get("message", "AUTHENTICATION_FAILED")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"{errormessage}"
            )

        uid=data["localId"]
        email=data["email"]
        idtoken=data["idToken"]

        userreference=db.collection("users").document(uid)
        userdocument=userreference.get()

        if userdocument.exists:
            userdata=userdocument.to_dict()
            role=userdata.get("role","admin")
        else:
            role="client"
            userreference.set({
            "uid":uid,
            "email":email,
            "role":role,
            })

        return AuthenticationResponse(
            access_token=idtoken,
            token_type="bearer",
            uid=uid,
            email=email,
            role=role,
            message="Authentication successful"
        )

{-# LANGUAGE OverloadedStrings #-}

module Web.Scotty.Identity (
     Username
   , Password
   , IsUser
   , getUsername
   , getPassword
   , IsSession
   , getIdentifier
   , configureAuth) where

import Control.Monad (liftM)
import Data.Maybe (fromMaybe)
import Web.Scotty
import Web.Scotty.Cookie
import Web.Cookie
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import qualified Data.ByteString as BT
import Data.UUID
import Data.Time

type Username = T.Text
type Password = BT.ByteString

-- | Typeclass that requires a getter for a Username and Password
class IsUser a where
  getUsername :: a -> Username
  getPassword :: a -> Password

-- | Typeclass that requires a getter for an identifier 
class IsSession a where
  getIdentifier :: a -> UUID

type GetSession b      = UUID -> IO (Maybe b)
type SessionToUser b a = b -> IO (Maybe a)
type RetrieveUser a    = Username -> IO (Maybe a)
type CreateSession a b = a -> IO b
type HashFunction      = BT.ByteString -> BT.ByteString


-- | Configure authentication, returns a series of items and function that can be used
--   to control protected routes and login / logout logic
configureAuth :: (IsUser a, IsSession b) =>
                 GetSession b
              -> SessionToUser b a
              -> RetrieveUser a
              -> CreateSession a b
              -> HashFunction
              -> ( (a -> ActionM ()) -> ActionM ()         -- Authorized route 
                 , (Maybe a -> ActionM ()) -> ActionM ()   -- Maybe Authorized route
                 , ActionM ()                              -- Login post
                 , ActionM ())                             -- Logout get
configureAuth getSession sessionToUser retrieveUser makeSession hash = 
    (_makeAuth, _makeAuthM, _postLogin, _logout)
    where
      _makeAuth  = makeAuth getSession sessionToUser
      _makeAuthM = makeAuthM getSession sessionToUser
      _postLogin = postLogin retrieveUser makeSession hash
      _logout    = removeLoginCookie


getMaybeUser getSession sessionToUser = do
  strToken  <- liftM (fromMaybe "") $ getCookie authCookie :: ActionM T.Text
  case fromText strToken of
      Nothing -> return Nothing
      Just token -> do
          mSession <- liftAndCatchIO $ getSession token
          case mSession of
              Nothing -> return Nothing
              Just session -> liftAndCatchIO $ sessionToUser session

makeAuth getSession sessionToUser route = do
  mUser <- getMaybeUser getSession sessionToUser
  case mUser of
      Nothing -> redirect "/login"
      Just user -> route user

makeAuthM getSession sessionToUser route = getMaybeUser getSession sessionToUser >>= route


postLogin :: (IsUser a, IsSession b) => RetrieveUser a -> CreateSession a b -> HashFunction -> ActionM ()
postLogin retrieveUser makeSession hash = do
    username <- param "username"
    password <- encodeUtf8 <$> param "password"
    mUser <- liftAndCatchIO $ retrieveUser username
    case mUser of
        Nothing -> redirect "/login"
        Just u  -> do
            case hash password == getPassword u of
                  False -> redirect "/login"
                  True  -> do
                        s <- liftAndCatchIO $ makeSession u
                        setLoginCookie s

setLoginCookie :: IsSession a => a -> ActionM ()
setLoginCookie session = setCookie $ createLoginCookie ((toText . getIdentifier) session)

removeLoginCookie :: ActionM ()
removeLoginCookie = deleteCookie authCookie

authCookie :: T.Text
authCookie = "Authorization"

createLoginCookie :: T.Text -> SetCookie
createLoginCookie value = def 
  { setCookieName = encodeUtf8 authCookie
  , setCookieValue = encodeUtf8 value
  , setCookieHttpOnly   = True }

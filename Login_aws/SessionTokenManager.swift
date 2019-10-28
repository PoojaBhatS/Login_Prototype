//
//  SessionManager.swift
//  STV Player
//
//  Created by Stewart Thomson on 21/08/2018.
//  Copyright © 2018 STV. All rights reserved.
//

import Foundation

class SessionTokenManager {

  typealias SessionManagerAccessTokenResponse = (_ accessToken: String?) -> Void

  let pool: AWSCognitoIdentityUserPool

  class var accessToken: String? {
    get {
      return AWSUICKeyChainStore().string(forKey: "stv_AccessToken")
    }
    set {
      AWSUICKeyChainStore().setString(newValue, forKey: "stv_AccessToken")
    }
  }

  class var expiryDate: Date? {
    get {
      return UserDefaults.standard.object(forKey: "stv_ExpiryDate") as? Date
    }
    set {
      UserDefaults.standard.set(newValue, forKey: "stv_ExpiryDate")
    }
  }

  class var refreshToken: String? {
    get {
      return AWSUICKeyChainStore().string(forKey: "stv_RefreshToken")
    }
    set {
      AWSUICKeyChainStore().setString(newValue, forKey: "stv_RefreshToken")
    }
  }

  init(pool: AWSCognitoIdentityUserPool) {
    self.pool = pool
  }

  func saveAuthResponse(authenticationResult: AWSCognitoIdentityProviderAuthenticationResultType) {
    SessionTokenManager.accessToken = authenticationResult.accessToken
    if let timeInterval = authenticationResult.expiresIn?.doubleValue {
      SessionTokenManager.expiryDate = Date().addingTimeInterval(timeInterval)
    }
    if let refreshToken = authenticationResult.refreshToken {
      SessionTokenManager.refreshToken = refreshToken
    }
  }

  func getAccessToken(callback: @escaping SessionManagerAccessTokenResponse) {
    if let accessToken = SessionTokenManager.accessToken, let expiryDate = SessionTokenManager.expiryDate {
      if expiryDate.timeIntervalSinceNow < 300 {
        if let refreshToken = SessionTokenManager.refreshToken {
          refreshSession(with: refreshToken, callback: callback)
          return
        } else {
          // Can't Refresh: Loggout
          callback(nil)
          return
        }
      } else {
        callback(accessToken)
        return
      }
    } else {
      if let refreshToken = SessionTokenManager.refreshToken {
        refreshSession(with: refreshToken, callback: callback)
      } else {
        // Can't Refresh: Loggout
        callback(nil)
        return
      }
    }
  }

  private func refreshSession(with token: String, callback: @escaping SessionManagerAccessTokenResponse) {

    SessionTokenManager.accessToken = nil

    let request = AWSCognitoIdentityProviderInitiateAuthRequest()!
    request.clientId = pool.userPoolConfiguration.clientId
    request.authFlow = .refreshTokenAuth
    request.authParameters = ["REFRESH_TOKEN": token]

    AWSCognitoIdentityProvider.default().initiateAuth(request).continueWith { (response) -> Any? in
      guard response.error == nil else {
        callback(nil)
        return nil
      }
      if let result = response.result {
        if let authenticationResult = result.authenticationResult {
          self.saveAuthResponse(authenticationResult: authenticationResult)
        }
      }
      callback(SessionTokenManager.accessToken)
      return nil
    }
  }
}

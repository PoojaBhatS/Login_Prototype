//
//  UserPasswordAuth.swift
//  STV Player
//
//  Created by Stewart Thomson on 20/08/2018.
//  Copyright © 2018 STV. All rights reserved.
//

import Foundation

class UserPasswordAuth {

  final private let email: String
  final private let password: String
  final private let pool: AWSCognitoIdentityUserPool

  init(email: String, password: String, pool: AWSCognitoIdentityUserPool) {
    self.email = email
    self.password = password
    self.pool = pool
  }

  func initiateAuth(callback: @escaping (_ success: Bool, _ error: Error?) -> Void) {
    let request = AWSCognitoIdentityProviderInitiateAuthRequest()!
    request.clientId = pool.userPoolConfiguration.clientId
    request.authFlow = .userPasswordAuth
    request.authParameters = ["USERNAME": email, "PASSWORD": password]

    AWSCognitoIdentityProvider.default().initiateAuth(request, completionHandler: { (response, error) in
      guard error == nil else {
        callback(false, error)
        return
      }

      if let response = response {
        if let authenticationResult = response.authenticationResult {
          SessionTokenManager(pool: self.pool).saveAuthResponse(authenticationResult: authenticationResult)
          callback(true, nil)
          return
        }
      }
      callback(false, nil)
    })
  }
}

/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

export function retrieveLoggedInUser() {
  return (req: Request, res: Response) => {
    let user
    let response: any
    const emptyUser = { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined }
    try {
      if (security.verify(req.cookies.token)) {
        user = security.authenticatedUsers.get(req.cookies.token)

        // Parse the fields parameter into an array, splitting by comma.
        // If not provided, both these variables will be undefined.
        const fieldsParam = req.query?.fields as string | undefined
        const requestedFields = fieldsParam ? fieldsParam.split(',').map(f => f.trim()) : []

        let baseUser: any = {}

        if (requestedFields.length > 0) {
          // When fields are specified, return only those fields
          const source = new Map<string, unknown>([
            ['id', user?.data?.id],
            ['email', user?.data?.email],
            ['lastLoginIp', user?.data?.lastLoginIp],
            ['profileImage', user?.data?.profileImage]
          ])
          // create allow list to only allow certain fields to be returned in the response
          const allowedFields = ['id', 'email', 'lastLoginIp', 'profileImage']
          const entries = requestedFields
            .filter(field => allowedFields.includes(field))
            .map(field => [field, source.get(field)] as const)
            .filter(([, value]) => value !== undefined)

          Object.assign(baseUser, Object.fromEntries(entries))
        } else {
          // If no fields parameter, return standard fields (not password field)
          baseUser = {
            id: user?.data?.id,
            email: user?.data?.email,
            lastLoginIp: user?.data?.lastLoginIp,
            profileImage: user?.data?.profileImage
          }
        }

        response = { user: baseUser }
      } else {
        response = { user: emptyUser }
      }
    } catch (err) {
      response = { user: emptyUser }
    }
    // Solve passwordHashLeakChallenge when password field is included in response
    challengeUtils.solveIf(challenges.passwordHashLeakChallenge, () => response?.user?.password)

    if (req.query.callback === undefined) {
      res.json(response)
    } else {
      challengeUtils.solveIf(challenges.emailLeakChallenge, () => { return true })
      res.jsonp(response)
    }
  }
}

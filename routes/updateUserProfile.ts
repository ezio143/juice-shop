/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import config from 'config'

function sanitizeHtml (value: string): string {
  return value.replace(/[^a-zA-Z0-9_]/g, '')
}

export function updateUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)

    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        next(new Error('User not found'))
        return
      }

      challengeUtils.solveIf(challenges.csrfChallenge, () => {
        const url = config.get<string>('challenges.overwriteUrlForCsrfChallenge')
        return ((req.headers.origin?.includes('://' + url.replace(/^https?:\/\//, ''))) ??
          (req.headers.referer?.includes('://' + url.replace(/^https?:\/\//, '')))) &&
          req.body.username !== user.username
      })

      // Validate and sanitize the username
      let newUsername = req.body.username
      if (typeof newUsername !== 'string' || newUsername.trim().length < 3 || newUsername.trim().length > 20) {
        return res.status(400).json({ error: 'Invalid username. Must be 3-20 characters.' })
      }
      newUsername = sanitizeHtml(newUsername.trim())
      const savedUser = await user.update({ username: newUsername })
      const userWithStatus = utils.queryResultToJson(savedUser)
      const updatedToken = security.authorize(userWithStatus)
      security.authenticatedUsers.put(updatedToken, userWithStatus)
      res.cookie('token', updatedToken)
      res.location(process.env.BASE_PATH + '/profile')
      res.redirect(process.env.BASE_PATH + '/profile')
    } catch (error) {
      next(error)
    }
  }
}

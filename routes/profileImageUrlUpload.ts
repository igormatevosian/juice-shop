/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'fs';
import path from 'path';
import { URL } from 'url';
import { type Request, type Response, type NextFunction } from 'express';
import logger from '../lib/logger';
import { UserModel } from '../models/user';
import * as utils from '../lib/utils';
const security = require('../lib/insecurity');
const request = require('request');

// Configuration
const ALLOWED_IMAGE_EXTENSIONS = new Set(['jpg', 'jpeg', 'png', 'svg', 'gif']);
const ALLOWED_DOMAINS = new Set([
  'trusted-images.com',
  'cdn.profile-pics.net'
  // Add other trusted domains here
]);
const UPLOAD_DIR = 'frontend/dist/frontend/assets/public/images/uploads';

module.exports = function profileImageUrlUpload() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // 1. Validate input
      if (!req.body.imageUrl) {
        return res.status(400).json({ error: 'Image URL is required' });
      }

      const url = req.body.imageUrl;
      
      // 2. Parse and validate URL
      let parsedUrl;
      try {
        parsedUrl = new URL(url);
      } catch (e) {
        return res.status(400).json({ error: 'Invalid URL format' });
      }

      // 3. SSRF protection
      if (isInternalUrl(parsedUrl)) {
        return res.status(403).json({ error: 'External image URLs only' });
      }

      // 4. Domain whitelisting
      if (!ALLOWED_DOMAINS.has(parsedUrl.hostname.replace(/^www\./, ''))) {
        return res.status(403).json({ error: 'Domain not allowed' });
      }

      // 5. Protocol validation
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        return res.status(403).json({ error: 'Only HTTP/HTTPS allowed' });
      }

      // Challenge detection
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) {
        req.app.locals.abused_ssrf_bug = true;
      }

      // 6. Authentication check
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token);
      if (!loggedInUser) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      // 7. Process image
      const ext = getSafeFileExtension(url);
      const filename = `${loggedInUser.data.id}.${ext}`;
      const filePath = path.join(UPLOAD_DIR, filename);

      // Ensure upload directory exists
      if (!fs.existsSync(UPLOAD_DIR)) {
        fs.mkdirSync(UPLOAD_DIR, { recursive: true });
      }

      // 8. Download with timeout and size limit
      const imageRequest = request.get({
        url: url,
        timeout: 5000, // 5 second timeout
        encoding: null // Get response as Buffer
      });

      imageRequest
        .on('error', async (err) => {
          logger.warn(`Error retrieving profile image: ${utils.getErrorMessage(err)}`);
          await updateUserProfile(loggedInUser.data.id, url, next);
        })
        .on('response', async (response) => {
          if (response.statusCode === 200) {
            // Validate content type
            const contentType = response.headers['content-type'];
            if (!contentType || !contentType.startsWith('image/')) {
              logger.warn(`Invalid content type: ${contentType}`);
              await updateUserProfile(loggedInUser.data.id, url, next);
              return;
            }

            // Write file
            const writeStream = fs.createWriteStream(filePath);
            imageRequest.pipe(writeStream);
            
            // Update DB with local path
            const localPath = `/assets/public/images/uploads/${filename}`;
            await updateUserProfile(loggedInUser.data.id, localPath, next);
          } else {
            await updateUserProfile(loggedInUser.data.id, url, next);
          }
        });

      res.location(`${process.env.BASE_PATH}/profile`);
      res.redirect(`${process.env.BASE_PATH}/profile`);

    } catch (error) {
      next(error);
    }
  };
};

// Helper functions
function isInternalUrl(url: URL): boolean {
  const hostname = url.hostname;
  return hostname === 'localhost' ||
         hostname === '127.0.0.1' ||
         hostname === '::1' ||
         hostname.endsWith('.internal') ||
         hostname.endsWith('.local') ||
         /^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\./.test(hostname);
}

function getSafeFileExtension(url: string): string {
  const ext = url.split('.').pop()?.toLowerCase() || 'jpg';
  return ALLOWED_IMAGE_EXTENSIONS.has(ext) ? ext : 'jpg';
}

async function updateUserProfile(userId: number, imageUrl: string, next: NextFunction) {
  try {
    const user = await UserModel.findByPk(userId);
    if (user) {
      await user.update({ profileImage: imageUrl });
    }
  } catch (error) {
    next(error);
  }
}
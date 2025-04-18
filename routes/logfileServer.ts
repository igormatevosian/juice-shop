/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path');
import fs = require('fs');
import { promisify } from 'util';
import { type Request, type Response, type NextFunction } from 'express';

const access = promisify(fs.access);
const stat = promisify(fs.stat);

module.exports = function serveLogFiles() {
  return async ({ params }: Request, res: Response, next: NextFunction) => {
    try {
      const file = params.file;
      
      // 1. Валидация имени файла
      if (!/^[a-zA-Z0-9_.-]+$/.test(file)) {
        return res.status(400).json({ error: 'Invalid file name' });
      }

      // 2. Построение безопасного пути
      const logsDir = path.resolve('logs');
      const filePath = path.join(logsDir, file);
      const resolvedPath = path.resolve(filePath);

      // 3. Проверка, что путь остается внутри logs директории
      if (!resolvedPath.startsWith(logsDir)) {
        return res.status(403).json({ error: 'Access denied' });
      }

      // 4. Проверка существования файла
      await access(filePath, fs.constants.F_OK);
      const stats = await stat(filePath);
      
      // 5. Проверка, что это файл (а не директория)
      if (!stats.isFile()) {
        return res.status(403).json({ error: 'Not a file' });
      }

      // 6. Безопасная отправка файла
      res.sendFile(filePath, {
        dotfiles: 'deny', // Запрещаем доступ к файлам, начинающимся с точки
        root: logsDir     // Явно указываем корневую директорию
      });
    } catch (error) {
      if (error.code === 'ENOENT') {
        return res.status(404).json({ error: 'File not found' });
      }
      next(error);
    }
  };
};

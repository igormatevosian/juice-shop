import path from 'path'
import { readFile } from 'fs/promises'
import { safeLoad } from 'js-yaml'
import logger from '../lib/logger'

export async function loadStaticData(file: string) {
  // 1. Нормализуем и проверяем входной параметр
  const normalizedFile = path.normalize(file).replace(/^(\.\.(\/|\\|$))+/g, '');
  
  // 2. Проверяем допустимые символы в имени файла
  if (!/^[a-zA-Z0-9-_]+$/.test(normalizedFile)) {
    throw new Error('Invalid file name');
  }

  // 3. Формируем безопасный путь
  const basePath = path.resolve('./data/static/');
  const filePath = path.join(basePath, `${normalizedFile}.yml`);
  
  // 4. Проверяем, что конечный путь находится внутри разрешенной директории
  if (!filePath.startsWith(basePath)) {
    throw new Error('Path traversal attempt detected');
  }

  try {
    const content = await readFile(filePath, 'utf8');
    return safeLoad(content);
  } catch (error) {
    logger.error(`Could not open file: "${filePath}"`, error);
    throw error; // Пробрасываем ошибку дальше для обработки
  }
}

export interface StaticUser {
  email: string
  password: string
  key: string
  role: 'admin' | 'customer' | 'deluxe' | 'accounting'

  username?: string
  profileImage?: string
  walletBalance?: number
  lastLoginIp?: string
  deletedFlag?: boolean
  totpSecret?: string
  customDomain?: boolean
  securityQuestion?: StaticUserSecurityQuestion
  feedback?: StaticUserFeedback
  address?: StaticUserAddress[]
  card?: StaticUserCard[]
}
export interface StaticUserSecurityQuestion {
  id: number
  answer: string
}
export interface StaticUserFeedback {
  comment: string
  rating: 1 | 2 | 3 | 4 | 5
}
export interface StaticUserAddress {
  fullName: string
  mobileNum: number
  zipCode: string
  streetAddress: string
  city: string
  state: string
  country: string
}
export interface StaticUserCard {
  fullName: string
  cardNum: number
  expMonth: number
  expYear: number
}
export async function loadStaticUserData (): Promise<StaticUser[]> {
  return await loadStaticData('users') as StaticUser[]
}

export interface StaticChallenge {
  name: string
  category: string
  tags?: string[]
  description: string
  difficulty: number
  hint: string
  hintUrl: string
  mitigationUrl: string
  key: string
  disabledEnv?: string[]
  tutorial?: {
    order: number
  }
}
export async function loadStaticChallengeData (): Promise<StaticChallenge[]> {
  return await loadStaticData('challenges') as StaticChallenge[]
}

export interface StaticDelivery {
  name: string
  price: number
  deluxePrice: number
  eta: number
  icon: string
}
export async function loadStaticDeliveryData (): Promise<StaticDelivery[]> {
  return await loadStaticData('deliveries') as StaticDelivery[]
}

export interface StaticSecurityQuestions {
  question: string
}
export async function loadStaticSecurityQuestionsData (): Promise<StaticSecurityQuestions[]> {
  return await loadStaticData('securityQuestions') as StaticSecurityQuestions[]
}

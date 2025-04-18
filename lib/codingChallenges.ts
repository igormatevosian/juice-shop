import fs from 'fs';
import path from 'path'
import logger from './logger'
import { promisify } from 'util';

export const SNIPPET_PATHS = Object.freeze(['./server.ts', './routes', './lib', './data', './data/static/web3-snippets', './frontend/src/app', './models'])

interface FileMatch {
  path: string
  content: string
}

interface CachedCodeChallenge {
  snippet: string
  vulnLines: number[]
  neutralLines: number[]
}

const readFile = promisify(fs.readFile);
const readdir = promisify(fs.readdir);
const lstat = promisify(fs.lstat);

export const findFilesWithCodeChallenges = async (paths: readonly string[]): Promise<FileMatch[]> => {
  const matches: FileMatch[] = [];
  
  for (const currPath of paths) {
    try {
      const stats = await lstat(currPath);
      
      if (stats.isDirectory()) {
        // Безопасное чтение директории
        const files = await readdir(currPath);
        
        // Безопасное построение путей
        const safePaths = files.map(file => {
          const fullPath = path.join(currPath, file);
          
          // Проверка, что путь остается внутри разрешенной директории
          const resolvedPath = path.resolve(fullPath);
          if (!resolvedPath.startsWith(path.resolve(currPath))) {
            throw new Error(`Path traversal attempt detected: ${file}`);
          }
          
          return resolvedPath;
        });

        const moreMatches = await findFilesWithCodeChallenges(safePaths);
        matches.push(...moreMatches);
      } else {
        // Проверка файла на наличие маркеров уязвимостей
        const code = await readFile(currPath, 'utf8');
        if (
          code.includes('// vuln-code' + '-snippet start') ||
          code.includes('# vuln-code' + '-snippet start')
        ) {
          matches.push({ path: currPath, content: code });
        }
      }
    } catch (e) {
      logger.warn(`File ${currPath} could not be processed. Error: ${e.message}`);
    }
  }

  return matches;
};

function getCodeChallengesFromFile (file: FileMatch) {
  const fileContent = file.content

  // get all challenges which are in the file by a regex capture group
  const challengeKeyRegex = /[/#]{0,2} vuln-code-snippet start (?<challenges>.*)/g
  const challenges = [...fileContent.matchAll(challengeKeyRegex)]
    .flatMap(match => match.groups?.challenges?.split(' ') ?? [])
    .filter(Boolean)

  return challenges.map((challengeKey) => getCodingChallengeFromFileContent(fileContent, challengeKey))
}

function getCodingChallengeFromFileContent (source: string, challengeKey: string) {
  const snippets = source.match(`[/#]{0,2} vuln-code-snippet start.*${challengeKey}([^])*vuln-code-snippet end.*${challengeKey}`)
  if (snippets == null) {
    throw new BrokenBoundary('Broken code snippet boundaries for: ' + challengeKey)
  }
  let snippet = snippets[0] // TODO Currently only a single code snippet is supported
  snippet = snippet.replace(/\s?[/#]{0,2} vuln-code-snippet start.*[\r\n]{0,2}/g, '')
  snippet = snippet.replace(/\s?[/#]{0,2} vuln-code-snippet end.*/g, '')
  snippet = snippet.replace(/.*[/#]{0,2} vuln-code-snippet hide-line[\r\n]{0,2}/g, '')
  snippet = snippet.replace(/.*[/#]{0,2} vuln-code-snippet hide-start([^])*[/#]{0,2} vuln-code-snippet hide-end[\r\n]{0,2}/g, '')
  snippet = snippet.trim()

  let lines = snippet.split('\r\n')
  if (lines.length === 1) lines = snippet.split('\n')
  if (lines.length === 1) lines = snippet.split('\r')
  const vulnLines = []
  const neutralLines = []
  // Предопределенные безопасные регулярные выражения
  const VULN_LINE_REGEX = /vuln-code-snippet vuln-line ([\w-]+)/;
  const NEUTRAL_LINE_REGEX = /vuln-code-snippet neutral-line ([\w-]+)/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    // Проверка уязвимых строк
    const vulnMatch = VULN_LINE_REGEX.exec(line);
    if (vulnMatch && vulnMatch[1] === challengeKey) {
      vulnLines.push(i + 1);
      continue;
    }
    
    // Проверка нейтральных строк
    const neutralMatch = NEUTRAL_LINE_REGEX.exec(line);
    if (neutralMatch && neutralMatch[1] === challengeKey) {
      neutralLines.push(i + 1);
    }
  }
  snippet = snippet.replace(/\s?[/#]{0,2} vuln-code-snippet vuln-line.*/g, '')
  snippet = snippet.replace(/\s?[/#]{0,2} vuln-code-snippet neutral-line.*/g, '')
  return { challengeKey, snippet, vulnLines, neutralLines }
}

class BrokenBoundary extends Error {
  constructor (message: string) {
    super(message)
    this.name = 'BrokenBoundary'
    this.message = message
  }
}

// dont use directly, use getCodeChallenges getter
let _internalCodeChallenges: Map<string, CachedCodeChallenge> | null = null
export async function getCodeChallenges (): Promise<Map<string, CachedCodeChallenge>> {
  if (_internalCodeChallenges === null) {
    _internalCodeChallenges = new Map<string, CachedCodeChallenge>()
    const filesWithCodeChallenges = await findFilesWithCodeChallenges(SNIPPET_PATHS)
    for (const fileMatch of filesWithCodeChallenges) {
      for (const codeChallenge of getCodeChallengesFromFile(fileMatch)) {
        _internalCodeChallenges.set(codeChallenge.challengeKey, {
          snippet: codeChallenge.snippet,
          vulnLines: codeChallenge.vulnLines,
          neutralLines: codeChallenge.neutralLines
        })
      }
    }
  }
  return _internalCodeChallenges
}

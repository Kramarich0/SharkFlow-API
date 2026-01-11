/**
 * @module validators/board
 * @description Валидаторы для досок.
 */
import { validateBooleanField, validateTitleField } from './commonValidators.js';

/**
 * Проверяет, является ли строка валидным UUID v4
 * @param {string} uuid - UUID для проверки
 * @returns {boolean} true, если uuid валиден
 */
export const isValidUUID = (uuid) => {
  if (!uuid || typeof uuid !== 'string') {
    return false;
  }
  const uuidRegex =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
};

/**
 * Очищает строку от потенциально опасных символов и скриптов
 * @param {string} input - Входная строка
 * @returns {string} Очищенная строка
 */
export const sanitizeInput = (input) => {
  if (typeof input !== 'string') return '';

  return input
    .trim()
    .replace(/[<>]/g, '')
    .replace(/\b(?:javascript|data|vbscript):/gi, '')
    .replace(/on\w+=/gi, '')
    .substring(0, 64);
};

/**
 * Проверяет, является ли строка валидным hex-цветом (3 или 6 символов)
 * @param {string} color - Цвет для проверки
 * @returns {boolean} true, если цвет валиден
 */
export const isValidColor = (color) => {
  if (typeof color !== 'string') return false;
  const cleaned = color.trim().replace(/^#/, '');
  return /^([0-9a-f]{3}|[0-9a-f]{6})$/i.test(cleaned);
};

/**
 * Очищает строку цвета от символа #
 * @param {string} color - Цвет
 * @returns {string} Очищенный цвет
 */
export const sanitizeColor = (color) => {
  if (typeof color !== 'string') return '';
  return color.trim().replace(/^#/, '');
};

/**
 * Валидация названия доски
 * @param {string} title - Название доски
 * @returns {Object} Результат валидации {isValid: boolean, value?: string, error?: string}
 */
export const validateBoardTitle = (title) => validateTitleField(title, 'доски', 64);

/**
 * Валидация параметров пагинации
 * @param {number|string} page - Номер страницы
 * @param {number|string} limit - Лимит на страницу
 * @returns {{page: number, limit: number}} Корректные параметры пагинации
 */
export const validatePaginationParams = (page, limit) => {
  const validPage = Math.max(1, parseInt(page) || 1);
  const validLimit = Math.min(50, Math.max(1, parseInt(limit) || 10));
  return { page: validPage, limit: validLimit };
};

export { validateBooleanField };

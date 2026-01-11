/**
 * @module validators/task
 * @description Валидаторы для задач.
 */
import { validateBooleanField, validateTitleField } from './commonValidators.js';
import sanitizeHtml from 'sanitize-html';

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

  const trimmed = input.trim();
  const sanitized = sanitizeHtml(trimmed, {
    allowedTags: [],
    allowedAttributes: {},
  });

  return sanitized.substring(0, 64);
};

/**
 * Валидация названия задачи
 * @param {string} title - Название задачи
 * @returns {Object} Результат валидации {isValid: boolean, value?: string, error?: string}
 */
export const validateTaskTitle = (title) => validateTitleField(title, 'задачи', 64);

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

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Валидация и нормализация входных данных
      let criteria = typeof req.query.q === 'string' ? req.query.q.trim() : '';
      criteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200);

      // Проверка допустимых критериев поиска (исправленная логика)
      if (!criteria.startsWith("apple") && !criteria.startsWith("orange")) {
        return res.status(400).json({ error: "Only apple or orange related searches are allowed" });
      }

      // Безопасный параметризованный запрос
      const [products] = await models.sequelize.query(
        `SELECT * FROM Products 
         WHERE ((name LIKE ? OR description LIKE ?) AND deletedAt IS NULL) 
         ORDER BY name`,
        {
          replacements: [`%${criteria}%`, `%${criteria}%`],
          type: models.sequelize.QueryTypes.SELECT
        }
      );

      // Обработка и локализация результатов
      const processedProducts = products.map(product => ({
        ...product,
        name: req.__(product.name),
        description: req.__(product.description)
      }));

      res.json(utils.queryResultToJson(processedProducts));
    } catch (error) {
      next(error.parent || error);
    }
  };
};
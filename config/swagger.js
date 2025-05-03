const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

// Swagger definition
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'QuantrustPKI Assessment API Documentation',
      version: '1.0.0',
      description: 'API documentation for routes',
      contact: {
        name: 'API Support',
        email: 'work.muhammadahsan@gmail.com'
      }
    },
    servers: [
      {
        url: 'http://localhost:8000/api/v1',
        description: 'Development server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      }
    },
    security: [{
      bearerAuth: []
    }]
  },
  // Path to the API docs
  apis: [
    './docs/**/*.yaml',
    './routes/*.js'
  ]
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

const swaggerDocs = (app) => {
  // Swagger page
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

  // Docs in JSON format
  app.get('/api-docs.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerSpec);
  });

  console.log(`Swagger docs available at http://localhost:${process.env.SERVER_PORT || 8000}/api-docs`);
};

module.exports = { swaggerDocs };
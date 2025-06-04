// Example of a custom command for login
Cypress.Commands.add('login', (email: string, password: string) => {
  cy.visit('/login')
  cy.get('input[name="email"]').type(email)
  cy.get('input[name="password"]').type(password)
  cy.get('button[type="submit"]').click()
})

// Example of a custom command for API calls
Cypress.Commands.add('apiLogin', (email: string, password: string) => {
  cy.request({
    method: 'POST',
    url: '/api/auth/login',
    body: {
      email,
      password,
    },
  }).then((response) => {
    window.localStorage.setItem('token', response.body.token)
  })
}) 
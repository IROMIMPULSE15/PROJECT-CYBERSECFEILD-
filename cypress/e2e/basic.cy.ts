describe('Basic Navigation', () => {
  it('should visit the home page', () => {
    cy.visit('/')
    cy.get('body').should('exist')
  })

  // Add more E2E test cases here
}) 
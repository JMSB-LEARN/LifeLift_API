async function testRegister() {
  try {
    const res = await fetch('http://localhost:3000/api/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username: `testuser_${Date.now()}`,
        email: `test_${Date.now()}@test.com`,
        password: 'password123',
        first_name: 'Test',
        surname: 'User',
        document_number: `${Date.now()}`.slice(0, 8) + 'A',
        document_type: 'DNI',
        birth_date: '2000-01-01'
      })
    });
    const data = await res.json();
    if (res.ok) {
      console.log('Registration success:', data);
    } else {
      console.error('Registration failed:', data);
    }
  } catch (err) {
    console.error('Registration failed:', err.message);
  }
}

testRegister();

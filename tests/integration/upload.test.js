const request = require('supertest');
const httpStatus = require('http-status');

jest.mock('pompelmi', () => ({
  scanBytes: jest.fn(),
  STRICT_PUBLIC_UPLOAD: 'strict_public_upload',
}));

const { scanBytes } = require('pompelmi');
const app = require('../../src/app');
const setupTestDB = require('../utils/setupTestDB');
const { userOne, admin, insertUsers } = require('../fixtures/user.fixture');
const { userOneAccessToken, adminAccessToken } = require('../fixtures/token.fixture');

setupTestDB();

describe('Upload routes', () => {
  describe('POST /v1/upload', () => {
    beforeEach(() => {
      scanBytes.mockReset();
    });

    test('should return 401 error if access token is missing', async () => {
      await request(app)
        .post('/v1/upload')
        .attach('file', Buffer.from('fake file content'), 'test.pdf')
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 400 error if no file is attached', async () => {
      await insertUsers([userOne]);

      await request(app)
        .post('/v1/upload')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if file type is not allowed', async () => {
      await insertUsers([userOne]);

      await request(app)
        .post('/v1/upload')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .attach('file', Buffer.from('fake file content'), {
          filename: 'test.exe',
          contentType: 'application/x-msdownload',
        })
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 200 and accept a clean valid file', async () => {
      await insertUsers([userOne]);

      scanBytes.mockResolvedValue({
        verdict: 'clean',
        reasons: [],
      });

      const res = await request(app)
        .post('/v1/upload')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .attach('file', Buffer.from('fake pdf content'), {
          filename: 'test.pdf',
          contentType: 'application/pdf',
        })
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        message: 'File accepted',
        filename: 'test.pdf',
      });
    });

    test('should return 422 error if file is malicious', async () => {
      await insertUsers([userOne]);

      scanBytes.mockResolvedValue({
        verdict: 'malicious',
        reasons: ['malware detected'],
      });

      await request(app)
        .post('/v1/upload')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .attach('file', Buffer.from('malicious content'), {
          filename: 'virus.pdf',
          contentType: 'application/pdf',
        })
        .expect(httpStatus.UNPROCESSABLE_ENTITY);
    });

    test('should return 422 error if file is suspicious', async () => {
      await insertUsers([userOne]);

      scanBytes.mockResolvedValue({
        verdict: 'suspicious',
        reasons: ['risky archive structure'],
      });

      await request(app)
        .post('/v1/upload')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .attach('file', Buffer.from('suspicious content'), {
          filename: 'suspicious.pdf',
          contentType: 'application/pdf',
        })
        .expect(httpStatus.UNPROCESSABLE_ENTITY);
    });

    test('should return 422 error if scan returns ScanError verdict', async () => {
      await insertUsers([userOne]);

      scanBytes.mockResolvedValue({
        verdict: 'ScanError',
        reasons: ['scanner could not complete'],
      });

      await request(app)
        .post('/v1/upload')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .attach('file', Buffer.from('some content'), {
          filename: 'test.pdf',
          contentType: 'application/pdf',
        })
        .expect(httpStatus.UNPROCESSABLE_ENTITY);
    });

    test('should return 422 error if scan throws an error', async () => {
      await insertUsers([userOne]);

      scanBytes.mockRejectedValue(new Error('Scan timeout'));

      await request(app)
        .post('/v1/upload')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .attach('file', Buffer.from('some content'), {
          filename: 'test.pdf',
          contentType: 'application/pdf',
        })
        .expect(httpStatus.UNPROCESSABLE_ENTITY);
    });

    test('should return 422 error if scan returns an unexpected verdict', async () => {
      await insertUsers([userOne]);

      scanBytes.mockResolvedValue({
        verdict: 'unknown',
        reasons: ['unexpected scanner verdict'],
      });

      await request(app)
        .post('/v1/upload')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .attach('file', Buffer.from('some content'), {
          filename: 'test.pdf',
          contentType: 'application/pdf',
        })
        .expect(httpStatus.UNPROCESSABLE_ENTITY);
    });

    test('should return 200 if admin uploads a clean valid file', async () => {
      await insertUsers([admin]);

      scanBytes.mockResolvedValue({
        verdict: 'clean',
        reasons: [],
      });

      const res = await request(app)
        .post('/v1/upload')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .attach('file', Buffer.from('fake pdf content'), {
          filename: 'admin-test.pdf',
          contentType: 'application/pdf',
        })
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        message: 'File accepted',
        filename: 'admin-test.pdf',
      });
    });

    test('should return 200 for allowed image file types', async () => {
      await insertUsers([userOne]);

      scanBytes.mockResolvedValue({
        verdict: 'clean',
        reasons: [],
      });

      const res = await request(app)
        .post('/v1/upload')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .attach('file', Buffer.from('fake image content'), {
          filename: 'photo.jpeg',
          contentType: 'image/jpeg',
        })
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        message: 'File accepted',
        filename: 'photo.jpeg',
      });
    });
  });
});

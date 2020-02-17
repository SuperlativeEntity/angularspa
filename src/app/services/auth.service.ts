import { HttpClient, HttpParams } from '@angular/common/http';
import { EventEmitter, Injectable } from '@angular/core';
import { LocalStorageService } from 'angular-2-local-storage';
import * as CryptoJS from 'crypto-js';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { environment } from 'src/environments/environment';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  public onLogin: EventEmitter<boolean> = new EventEmitter();
  public onLogout: EventEmitter<boolean> = new EventEmitter();

  private isAuth = false;

  constructor(
    private http: HttpClient,
    private storage: LocalStorageService
  ) {
    const accessToken: string = this.storage.get('accessToken') || '';
    this.isAuth = accessToken.length > 0;
  }

  get isAuthenticated() {
    return this.isAuth;
  }

  public getLoginUrl(): string {

    const state = this.strRandom(40);
    const codeVerifier = this.strRandom(128);

    this.storage.set('state', state);
    this.storage.set('codeVerifier', codeVerifier);

    const codeVerifierHash = CryptoJS.SHA256(codeVerifier).toString(CryptoJS.enc.Base64);

    const codeChallenge = codeVerifierHash
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

    const params = [
      'response_type=code',
      'state=' + state,
      'client_id=' + environment.oauthClientId,
      'scope=read_user_data write_user_data',
      'code_challenge=' + codeChallenge,
      'code_challenge_method=S256',
      'redirect_uri=' + encodeURIComponent(environment.oauthCallbackUrl),
    ];

    return environment.oauthLoginUrl + '?' + params.join('&');
  }

  public getAccessToken(code: string, state: string): Observable<any> {

    if (state !== this.storage.get('state')) {
      return new Observable(o => {
        o.next(false);
      });
    }

    const payload = new HttpParams()
      .append('grant_type', 'authorization_code')
      .append('code', code)
      .append('code_verifier', this.storage.get('codeVerifier'))
      .append('redirect_uri', environment.oauthCallbackUrl)
      .append('client_id', environment.oauthClientId);

    return this.http.post(environment.oauthTokenUrl, payload, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    }).pipe(map((response: any) => {
      this.storage.set('tokenType', response.token_type);
      this.storage.set('expiresIn', response.expires_in);
      this.storage.set('accessToken', response.access_token);
      this.storage.set('refreshToken', response.refresh_token);
      this.isAuth = true;
      this.onLogin.emit(true);
      return response;
    }));
  }

  public logout() {
    this.storage.clearAll();
    this.isAuth = false;
    this.onLogout.emit(false);
  }

  private strRandom(length: number) {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
  }
}
import { HttpErrorResponse, HttpEventType } from '@angular/common/http';
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ToastrService } from 'ngx-toastr';
import { FileUploadHandlerEvent } from 'primeng/fileupload';
import { map, Observable, shareReplay, startWith } from 'rxjs';
import { GithubUpdateService } from 'src/app/services/github-update.service';
import { LoadingService } from 'src/app/services/loading.service';
import { SystemService } from 'src/app/services/system.service';
import { eASICModel } from 'src/models/enum/eASICModel';

@Component({
  selector: 'app-settings',
  templateUrl: './settings.component.html',
  styleUrls: ['./settings.component.scss']
})
export class SettingsComponent {

  public form!: FormGroup;

  public firmwareUpdateProgress: number | null = null;
  public websiteUpdateProgress: number | null = null;

  public deviceModel: string = "";
  public devToolsOpen: boolean = false;
  public eASICModel = eASICModel;
  public ASICModel!: eASICModel;

  public checkLatestRelease: boolean = false;
  public latestRelease$: Observable<any>;
  public expectedFileName: string = "";

  public info$: Observable<any>;

  constructor(
    private fb: FormBuilder,
    private systemService: SystemService,
    private toastr: ToastrService,
    private toastrService: ToastrService,
    private loadingService: LoadingService,
    private githubUpdateService: GithubUpdateService
  ) {



    window.addEventListener('resize', this.checkDevTools);
    this.checkDevTools();

    this.latestRelease$ = this.githubUpdateService.getReleases().pipe(map(releases => {
      return releases[0];
    }));

    this.info$ = this.systemService.getInfo(0).pipe(shareReplay({refCount: true, bufferSize: 1}))


      this.info$.pipe(this.loadingService.lockUIUntilComplete())
      .subscribe(info => {
        this.deviceModel = info.deviceModel;
        this.ASICModel = info.ASICModel;
        this.form = this.fb.group({
          flipscreen: [info.flipscreen == 1],
          invertscreen: [info.invertscreen == 1],
          autoscreenoff: [info.autoscreenoff == 0],
          stratumURL: [info.stratumURL, [
            Validators.required,
            Validators.pattern(/^(?!.*stratum\+tcp:\/\/).*$/),
            Validators.pattern(/^[^:]*$/),
          ]],
          stratumPort: [info.stratumPort, [
            Validators.required,
            Validators.pattern(/^[^:]*$/),
            Validators.min(0),
            Validators.max(65353)
          ]],
          stratumUser: [info.stratumUser, [Validators.required]],
          stratumPassword: ['*****', [Validators.required]],
          ssid: [info.ssid, [Validators.required]],
          wifiPass: ['*****'],
          coreVoltage: [info.coreVoltage, [Validators.required]],
          frequency: [info.frequency, [Validators.required]],
          jobInterval: [info.jobInterval, [Validators.required]],
          autofanspeed: [info.autofanspeed == 1, [Validators.required]],
          invertfanpolarity: [info.invertfanpolarity == 1, [Validators.required]],
          fanspeed: [info.fanspeed, [Validators.required]],
        });

        this.form.controls['autofanspeed'].valueChanges.pipe(
          startWith(this.form.controls['autofanspeed'].value)
        ).subscribe(autofanspeed => {
          if (autofanspeed) {
            this.form.controls['fanspeed'].disable();
          } else {
            this.form.controls['fanspeed'].enable();
          }
        });
        // Replace 'γ' with 'Gamma' if present
        this.expectedFileName = `esp-miner-${this.deviceModel}.bin`.replace('γ', 'Gamma');
      });

  }
  private checkDevTools = () => {
    if (
      window.outerWidth - window.innerWidth > 160 ||
      window.outerHeight - window.innerHeight > 160
    ) {
      this.devToolsOpen = true;
    } else {
      this.devToolsOpen = false;
    }
  };

  public updateSystem() {

    const form = this.form.getRawValue();

    form.frequency = parseInt(form.frequency);
    form.coreVoltage = parseInt(form.coreVoltage);
    form.jobInterval = parseInt(form.jobInterval);

    // bools to ints
    form.flipscreen = form.flipscreen == true ? 1 : 0;
    form.invertscreen = form.invertscreen == true ? 1 : 0;
    form.invertfanpolarity = form.invertfanpolarity == true ? 1 : 0;
    form.autofanspeed = form.autofanspeed == true ? 1 : 0;
    form.autoscreenoff = form.autoscreenoff == true ? 1 : 0;

    // Allow an empty wifi password
    form.wifiPass = form.wifiPass == null ? '' : form.wifiPass;

    if (form.wifiPass === '*****') {
      delete form.wifiPass;
    }
    if (form.stratumPassword === '*****') {
      delete form.stratumPassword;
    }

    if (form.fallbackStratumPassword === '*****') {
      delete form.fallbackStratumPassword;
    }

    this.systemService.updateSystem(undefined, form)
      .pipe(this.loadingService.lockUIUntilComplete())
      .subscribe({
        next: () => {
          this.toastr.success('Success!', 'Saved.');
        },
        error: (err: HttpErrorResponse) => {
          this.toastr.error('Error.', `Could not save. ${err.message}`);
        }
      });
  }

  otaUpdate(event: FileUploadHandlerEvent) {
    const file = event.files[0];

    if (file.name !== this.expectedFileName) {
      this.toastrService.error(`Incorrect file, looking for ${this.expectedFileName}.`, 'Error');
      return;
    }

    this.systemService.performOTAUpdate(file)
      .pipe(this.loadingService.lockUIUntilComplete())
      .subscribe({
        next: (event) => {
          if (event.type === HttpEventType.UploadProgress) {
            this.firmwareUpdateProgress = Math.round((event.loaded / (event.total as number)) * 100);
          } else if (event.type === HttpEventType.Response) {
            if (event.ok) {
              this.toastrService.success('Firmware updated', 'Success!');
            } else {
              this.toastrService.error(event.statusText, 'Error');
            }
          } else if (event instanceof HttpErrorResponse) {
            this.toastrService.error(event.error, 'Error');
          }
        },
        error: (err) => {
          this.toastrService.error(err.error, 'Error');
        },
        complete: () => {
          this.firmwareUpdateProgress = null;
        }
      });
  }

  otaWWWUpdate(event: FileUploadHandlerEvent) {
    const file = event.files[0];
    if (file.name != 'www.bin') {
      this.toastrService.error('Incorrect file, looking for www.bin.', 'Error');
      return;
    }

    this.systemService.performWWWOTAUpdate(file)
      .pipe(
        this.loadingService.lockUIUntilComplete(),
      ).subscribe({
        next: (event) => {
          if (event.type === HttpEventType.UploadProgress) {
            this.websiteUpdateProgress = Math.round((event.loaded / (event.total as number)) * 100);
          } else if (event.type === HttpEventType.Response) {
            if (event.ok) {
              setTimeout(() => {
                this.toastrService.success('Website updated', 'Success!');
                window.location.reload();
              }, 1000);

            } else {
              this.toastrService.error(event.statusText, 'Error');
            }
          }
          else if (event instanceof HttpErrorResponse)
          {
            this.toastrService.error(event.error, 'Error');
          }
        },
        error: (err) => {
          this.toastrService.error(err.error, 'Error');
        },
        complete: () => {
          this.websiteUpdateProgress = null;
        }
      });
  }

  public restart() {
    this.systemService.restart().subscribe(res => {

    });
    this.toastr.success('Success!', 'Bitaxe restarted');
  }





}

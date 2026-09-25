export type Counts=Record<string,number>
export type LatestScan={id:number;status:JobStatus;progress:number;stage:string;message:string;queued_at:string;started_at?:string;finished_at?:string;error?:string;coverage_warning?:string;counts:Counts;total:number}
export type GroupRef={id:number;name:string;color:GroupColor}
export type ArchiveSourceType='upload'|'mounted'|'report'
export type ImageArchive={id:number;name:string;source:ArchiveSourceType;size:number;modified_at:string;latest_scan:LatestScan|null;groups:GroupRef[]}
export type Overview={image_count:number;scanned_count:number;total_findings:number;severity:Counts;statuses:Counts;most_vulnerable:{image_id:number;name:string;total:number}[];risk_packages:{name:string;total:number;critical:number}[]}
export type Finding={id:number;target:string;vulnerability_id:string;package_name:string;installed_version:string;fixed_version:string;severity:string;title:string;description:string;primary_url:string}
export type FindingFilterOptions={packages:string[];targets:string[]}
export type ImageDetail=ImageArchive&{history:{id:number;status:JobStatus;progress:number;stage:string;message:string;queued_at:string;started_at?:string;finished_at?:string;error?:string;coverage_warning?:string}[]}
export type PackageItem={name:string;version:string;target:string;identifier:string;licenses:string;vulnerabilities?:number}
export type ScanComparison={base_scan_id:number;target_scan_id:number;summary:{new:number;resolved:number;unchanged:number;net:number};new:ComparisonFinding[];resolved:ComparisonFinding[]}
export type ComparisonFinding={vulnerability_id:string;severity:string;package_name:string;installed_version:string;fixed_version:string;target:string;title:string}
export type DiagnosticResult={overall:'ok'|'warning'|'error';checked_at:string;components:ComponentInfo[];checks:DiagnosticCheck[]}
export type DiagnosticCheck={id:string;label:string;status:'ok'|'warning'|'error'|'info';summary:string;details:Record<string,unknown>}
export type JobStatus='queued'|'running'|'completed'|'failed'|'cancelled'
export type ScanJob={id:number;image_id:number;image_name:string;status:JobStatus;progress:number;stage:string;message:string;queue_position:number|null;queued_at:string;started_at?:string;finished_at?:string;updated_at?:string;error?:string;coverage_warning?:string}
export type UploadJob={id:number;archive_name:string;status:JobStatus;progress:number;stage:string;message:string;bytes_received:number;total_bytes?:number;image_id?:number;image_count:number;queued_at:string;started_at?:string;finished_at?:string;updated_at?:string;error?:string}
export type MaintenanceJob={id:number;component:string;action:'check'|'update';status:JobStatus;progress:number;stage:string;message:string;result:Record<string,unknown>;error?:string;queued_at:string;started_at?:string;finished_at?:string;updated_at?:string}
export type ComponentInfo={id:string;name:string;description:string;required:boolean;bundled:boolean;installed:boolean;update_available:boolean;version?:string;updated_at?:string;next_update?:string;size_bytes?:number;path?:string;repositories?:string[];update_method?:string;metadata?:Record<string,unknown>;latest_job:MaintenanceJob|null}
export type UserRole='viewer'|'operator'|'admin'
export type ManagedUser={id:number;username:string;display_name:string;role:UserRole;active:boolean;totp_enabled:boolean;status:'active'|'pending_activation'|'activation_expired'|'disabled';activation_expires_at?:string;locked_until?:string;failed_login_count:number;created_at:string;updated_at:string}
export type UserActivation={user:ManagedUser;activation_code:string;activation_expires_at:string}
export type TwoFactorReissue={user:ManagedUser;reissue_code:string;reissue_expires_at:string}
export type ApiTokenStatus='active'|'expired'|'revoked'
export type ApiToken={id:number;name:string;token_prefix:string;created_at:string;expires_at:string;last_used_at?:string;revoked_at?:string;status:ApiTokenStatus}
export type IssuedApiToken=ApiToken&{token:string}
export type RemovedImage={id:number;name:string;source:ArchiveSourceType;removed_at?:string}
export type GroupColor='blue'|'emerald'|'amber'|'rose'|'violet'|'slate'
export type GroupScanStatus='empty'|'unscanned'|'partial'|'scanned'
export type ImageGroup={id:number;name:string;description:string;color:GroupColor;member_count:number;scanned_count:number;unscanned_count:number;scan_status:GroupScanStatus;highest_severity:string|null;severity:Counts;total_findings:number;created_at:string;updated_at:string}
export type GroupOverview={group_count:number;membership_count:number;scanned_membership_count:number;unscanned_membership_count:number;severity:Counts;total_findings:number;statuses:Record<GroupScanStatus,number>;groups:ImageGroup[]}
export type GroupMember={id:number;name:string;source:ArchiveSourceType;size:number;latest_status?:JobStatus;latest_scan_id?:number;counts:Counts;total:number}
export type ImageGroupDetail=ImageGroup&{members:GroupMember[]}
export type ServiceStatus={
  queue:{queued:number;running:number;active:number;capacity:number;utilization:number}
  workers:{available:number;configured:number}
  storage:{status:'ok'|'warning'|'critical';free_bytes:number;total_bytes:number;reserve_bytes:number;available_after_bytes:number;limiting_source:'host_probe'|'container_volume';container_volume_free_bytes:number;host_probe_free_bytes:number|null}
  events:{clients:number;capacity:number;dropped:number;rejected:number}
  limits:{scan_timeout_seconds:number;max_upload_bytes:number;max_upload_request_bytes:number;max_upload_files:number}
}

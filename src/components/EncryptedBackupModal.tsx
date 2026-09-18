import { useEffect, useRef, useState } from 'react';

interface Props {
  mode: 'export' | 'import';
  /** 提交口令；返回错误信息列表（空表示成功）。import 时第二参为文件文本。 */
  onSubmit: (password: string, confirm: string) => Promise<string[]>;
  onClose: () => void;
}

/**
 * 加密备份口令弹窗：
 * - 导出：输入并二次确认口令，校验通过后由 App 执行加密并下载信封；
 * - 导入：输入口令，由 App 解密信封并走现有 Plan 完整校验，成功才作为一次可撤销修订替换。
 * 口令仅保存在弹窗局部状态中，关闭即随组件卸载清除；绝不持久化。
 */
export default function EncryptedBackupModal({ mode, onSubmit, onClose }: Props) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [errors, setErrors] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const firstRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    firstRef.current?.focus();
  }, []);

  const isExport = mode === 'export';

  const submit = async () => {
    if (busy) return;
    const errs: string[] = [];
    if (password.length < 8) errs.push('口令至少需要 8 个字符');
    if (isExport && password !== confirm) errs.push('两次输入的口令不一致');
    if (errs.length > 0) {
      setErrors(errs);
      return;
    }
    setBusy(true);
    setErrors([]);
    try {
      const result = await onSubmit(password, confirm);
      if (result.length > 0) setErrors(result);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h3>{isExport ? '加密备份导出' : '加密备份导入'}</h3>
        <p className="muted">
          {isExport ? (
            <>
              使用 <strong>PBKDF2-SHA-256</strong>（200000 次迭代）从口令派生
              <strong> AES-GCM-256</strong> 密钥，随机生成 16 字节 salt 与 12 字节 IV，
              下载版本化 JSON 信封。口令不会被存储，<strong>丢失口令将无法恢复备份</strong>。
            </>
          ) : (
            <>
              输入导出时设置的口令以解密备份。信封仅接受本工具的版本化格式；
              字段或 Base64 非法、版本不支持、<strong>口令错误或密文被篡改</strong>时一律拒绝，
              当前规划保持不变。解密内容仍须通过现有规划完整校验，成功后作为
              <strong>一次可撤销修订</strong>替换当前规划。
            </>
          )}
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <label className="field">
            <span>口令（至少 8 个字符）</span>
            <input
              ref={firstRef}
              type="password"
              value={password}
              autoComplete="new-password"
              onChange={(e) => setPassword(e.target.value)}
              placeholder="输入备份口令"
            />
          </label>
          {isExport && (
            <label className="field">
              <span>确认口令</span>
              <input
                type="password"
                value={confirm}
                autoComplete="new-password"
                onChange={(e) => setConfirm(e.target.value)}
                placeholder="再次输入同一口令"
              />
            </label>
          )}
          {errors.length > 0 && (
            <ul className="errors">
              {errors.map((er, i) => (
                <li key={i}>{er}</li>
              ))}
            </ul>
          )}
          <div className="modal-actions">
            <button type="button" className="btn" onClick={onClose} disabled={busy}>
              取消
            </button>
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? '处理中…' : isExport ? '加密并下载' : '解密并导入'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

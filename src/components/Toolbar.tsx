import { useRef } from 'react';

interface Props {
  canUndo: boolean;
  canRedo: boolean;
  /** 多标签页分叉冲突解决期间锁定一切会修改规划的操作 */
  locked?: boolean;
  onUndo: () => void;
  onRedo: () => void;
  onExport: () => void;
  onImport: (text: string) => void;
  /** 打开加密备份导出弹窗（输入并确认口令） */
  onEncryptedExport: () => void;
  /** 选定加密备份文件后打开口令弹窗（App 暂存文件文本，不持久化） */
  onEncryptedImport: (text: string) => void;
  onLoadDemo: () => void;
  onReset: () => void;
  onPrefixPolicy: () => void;
}

export default function Toolbar(props: Props) {
  const fileRef = useRef<HTMLInputElement>(null);
  const encryptedFileRef = useRef<HTMLInputElement>(null);
  const locked = props.locked ?? false;

  const readFile = async (file: File | undefined): Promise<string | null> => {
    if (!file) return null;
    return file.text();
  };

  return (
    <header className="toolbar">
      <div className="brand">
        <span className="brand-icon">⌗</span>
        <h1>IPv4 子网规划台</h1>
      </div>
      <div className="toolbar-actions">
        <button className="btn" onClick={props.onUndo} disabled={!props.canUndo} title="Ctrl/Cmd+Z">
          ↩ 撤销
        </button>
        <button className="btn" onClick={props.onRedo} disabled={!props.canRedo} title="Ctrl/Cmd+Shift+Z">
          ↪ 重做
        </button>
        <span className="divider" />
        <button className="btn" onClick={props.onPrefixPolicy} title="对当前所有子网分配有序执行 prefix-list（不修改规划）">
          前缀策略校验
        </button>
        <span className="divider" />
        <button className="btn" onClick={props.onExport} title="导出未加密的规划 JSON">
          导出 JSON
        </button>
        <button className="btn" onClick={() => fileRef.current?.click()} disabled={locked} title={locked ? '冲突解决前不可导入' : '导入未加密的规划 JSON'}>
          导入 JSON
        </button>
        <input
          ref={fileRef}
          type="file"
          accept="application/json,.json"
          hidden
          onChange={(e) => {
            void (async () => {
              const text = await readFile(e.target.files?.[0]);
              if (text !== null) props.onImport(text);
              if (fileRef.current) fileRef.current.value = '';
            })();
          }}
        />
        <button
          className="btn"
          onClick={props.onEncryptedExport}
          title="以口令加密（PBKDF2-SHA-256 / AES-GCM-256）后下载版本化 JSON 信封"
        >
          🔒 加密备份
        </button>
        <button
          className="btn"
          onClick={() => encryptedFileRef.current?.click()}
          disabled={locked}
          title={
            locked
              ? '冲突解决前不可导入'
              : '选择加密备份信封（.json），再输入口令解密恢复'
          }
        >
          🔓 解密恢复
        </button>
        <input
          ref={encryptedFileRef}
          type="file"
          accept="application/json,.json"
          hidden
          onChange={(e) => {
            void (async () => {
              const text = await readFile(e.target.files?.[0]);
              if (text !== null) props.onEncryptedImport(text);
              if (encryptedFileRef.current) encryptedFileRef.current.value = '';
            })();
          }}
        />
        <span className="divider" />
        <button className="btn" onClick={props.onLoadDemo} disabled={locked}>
          载入示例
        </button>
        <button
          className="btn danger"
          disabled={locked}
          title={locked ? '冲突解决前不可清空' : undefined}
          onClick={() => {
            if (window.confirm('确定清空当前规划？（可撤销）')) props.onReset();
          }}
        >
          清空
        </button>
      </div>
    </header>
  );
}
